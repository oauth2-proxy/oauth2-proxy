package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	middlewareapi "github.com/Jing-ze/oauth2-proxy/pkg/apis/middleware"
	sessionsapi "github.com/Jing-ze/oauth2-proxy/pkg/apis/sessions"
	"github.com/Jing-ze/oauth2-proxy/pkg/util"

	oidc "github.com/Jing-ze/oauth2-proxy/pkg/providers/go_oidc"

	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	"github.com/justinas/alice"
)

// StoredSessionLoaderOptions contains all the requirements to construct
// a stored session loader.
// All options must be provided.
type StoredSessionLoaderOptions struct {
	// Session storage backend
	SessionStore sessionsapi.SessionStore

	// How often should sessions be refreshed
	RefreshPeriod time.Duration

	// Provider based session refreshing
	RefreshSession func(context.Context, *sessionsapi.SessionState, wrapper.HttpClient, func(args ...interface{}), uint32) (bool, error)

	// Provider based session validation.
	// If the session is older than `RefreshPeriod` but the provider doesn't
	// refresh it, we must re-validate using this validation.
	ValidateSession func(context.Context, *sessionsapi.SessionState) bool

	// Refresh request parameters
	RefreshClient         wrapper.HttpClient
	RefreshRequestTimeout uint32
}

// NewStoredSessionLoader creates a new StoredSessionLoader which loads
// sessions from the session store.
// If no session is found, the request will be passed to the nex handler.
// If a session was loader by a previous handler, it will not be replaced.
func NewStoredSessionLoader(opts *StoredSessionLoaderOptions) (*StoredSessionLoader, alice.Constructor) {
	ss := &StoredSessionLoader{
		store:                 opts.SessionStore,
		refreshPeriod:         opts.RefreshPeriod,
		sessionRefresher:      opts.RefreshSession,
		sessionValidator:      opts.ValidateSession,
		refreshClient:         opts.RefreshClient,
		refreshRequestTimeout: opts.RefreshRequestTimeout,
	}
	return ss, ss.loadSession
}

// storedSessionLoader is responsible for loading sessions from cookie
// identified sessions in the session store.
type StoredSessionLoader struct {
	store            sessionsapi.SessionStore
	refreshPeriod    time.Duration
	sessionRefresher func(context.Context, *sessionsapi.SessionState, wrapper.HttpClient, func(args ...interface{}), uint32) (bool, error)
	sessionValidator func(context.Context, *sessionsapi.SessionState) bool

	// Refresh request parameters
	refreshClient         wrapper.HttpClient
	refreshRequestTimeout uint32
	RemoteKeySet          *oidc.KeySet
	NeedsVerifier         bool
}

// loadSession attempts to load a session as identified by the request cookies.
// If no session is found, the request will be passed to the next handler.
// If a session was loader by a previous handler, it will not be replaced.
func (s *StoredSessionLoader) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)
		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		if scope.Session != nil {
			// The session was already loaded, pass to the next handler
			next.ServeHTTP(rw, req)
			return
		}
		proxyCallBack := func(args ...interface{}) {
			session := args[0].(*sessionsapi.SessionState)
			resumeFlag := args[1].(bool)
			updateKeysCallback := func(args ...interface{}) {
				resumeFlag := args[0].(bool)
				if session != nil && s.validateSession(req.Context(), session) != nil {
					session = nil
				}
				scope.Session = session
				next.ServeHTTP(rw, req)
				if resumeFlag {
					if rw.Header().Get(util.ResponseCode) == string(http.StatusOK) {
						proxywasm.ResumeHttpRequest()
					}
				}
			}
			keysNeedsUpdate := (session != nil) && (s.NeedsVerifier)
			if keysNeedsUpdate {
				if _, err := (*s.RemoteKeySet).VerifySignature(req.Context(), session.IDToken); err == nil {
					keysNeedsUpdate = false
				}
			}
			if keysNeedsUpdate {
				(*s.RemoteKeySet).UpdateKeys(s.refreshClient, s.refreshRequestTimeout, updateKeysCallback)
			} else {
				updateKeysCallback(resumeFlag)
			}
		}
		session, refreshed, err := s.getValidatedSession(rw, req, proxyCallBack)
		if err != nil && !errors.Is(err, http.ErrNoCookie) {
			// In the case when there was an error loading the session,
			// we should clear the session
			util.Logger.Errorf("Error loading cookied session: %v, removing session", err)
			err = s.store.Clear(rw, req)
			if err != nil {
				util.Logger.Errorf("Error removing session: %v", err)
			}
		}
		// proxyCallBack function will call after refresh session
		if refreshed {
			return
		}

		// Add the session to the scope if it was found
		proxyCallBack(session, false)
	})
}

// getValidatedSession is responsible for loading a session and making sure
// that is valid.
func (s *StoredSessionLoader) getValidatedSession(rw http.ResponseWriter, req *http.Request, callback func(args ...interface{})) (*sessionsapi.SessionState, bool, error) {
	session, err := s.store.Load(req)
	if err != nil || session == nil {
		// No session was found in the storage or error occurred, nothing more to do
		return nil, false, err
	}

	refreshed, err := s.refreshSessionIfNeeded(rw, req, session, callback)
	if err != nil {
		return nil, false, fmt.Errorf("error refreshing access token for session (%s): %v", session, err)
	}

	return session, refreshed, nil
}

// refreshSessionIfNeeded will attempt to refresh a session if the session
// is older than the refresh period.
// Success or fail, we will then validate the session.
func (s *StoredSessionLoader) refreshSessionIfNeeded(rw http.ResponseWriter, req *http.Request, session *sessionsapi.SessionState, callback func(args ...interface{})) (bool, error) {
	if !needsRefresh(s.refreshPeriod, session) {
		// Refresh is disabled or the session is not old enough, do nothing
		return false, nil
	}

	// We are holding the lock and the session needs a refresh
	util.Logger.Infof("Refreshing session - User: %s; SessionAge: %s", session.User, session.Age())

	if err := s.refreshSession(rw, req, session, callback); err != nil {
		// If a preemptive refresh fails, we still keep the session
		// if validateSession succeeds.
		util.Logger.Errorf("Unable to refresh session: %v", err)
		return false, err
	}

	// Validate all sessions after any Redeem/Refresh operation (fail or success)
	return true, nil
}

// needsRefresh determines whether we should attempt to refresh a session or not.
func needsRefresh(refreshPeriod time.Duration, session *sessionsapi.SessionState) bool {
	return refreshPeriod > time.Duration(0) && session.Age() > refreshPeriod
}

// refreshSession attempts to refresh the session with the provider
// and will save the session if it was updated.
func (s *StoredSessionLoader) refreshSession(rw http.ResponseWriter, req *http.Request, session *sessionsapi.SessionState, callback func(args ...interface{})) error {
	refreshedCallBack := func(args ...interface{}) {
		session := args[0].(*sessionsapi.SessionState)
		session.CreatedAtNow()
		// Because the session was refreshed, make sure to save it
		err := s.store.Save(rw, req, session)
		if err != nil {
			util.Logger.Errorf("error saving session: %v", err)
		}
	}
	combinedCallBack := util.Combine(refreshedCallBack, callback)
	refreshed, err := s.sessionRefresher(req.Context(), session, s.refreshClient, combinedCallBack, s.refreshRequestTimeout)
	if err != nil {
		return err
	}

	// Session not refreshed, nothing to persist.
	if !refreshed {
		return nil
	}
	return nil
}

// validateSession checks whether the session has expired and performs
// provider validation on the session.
// An error implies the session is no longer valid.
func (s *StoredSessionLoader) validateSession(ctx context.Context, session *sessionsapi.SessionState) error {
	if session.IsExpired() {
		return errors.New("session is expired")
	}

	if !s.sessionValidator(ctx, session) {
		return errors.New("session is invalid")
	}

	return nil
}
