package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers/utils"
)

const (
	// When attempting to obtain the lock, if it's not done before this timeout
	// then exit and fail the refresh attempt.
	// TODO: This should probably be configurable by the end user.
	sessionRefreshObtainTimeout = 5 * time.Second

	// Maximum time allowed for a session refresh attempt.
	// If the refresh request isn't finished within this time, the lock will be
	// released.
	// TODO: This should probably be configurable by the end user.
	sessionRefreshLockDuration = 2 * time.Second

	// How long to wait after failing to obtain the lock before trying again.
	// TODO: This should probably be configurable by the end user.
	sessionRefreshRetryPeriod = 10 * time.Millisecond
)

// StoredSessionLoaderOptions contains all of the requirements to construct
// a stored session loader.
// All options must be provided.
type StoredSessionLoaderOptions struct {
	// Session storage backend
	SessionStore sessionsapi.SessionStore

	// How often should sessions be refreshed
	RefreshPeriod time.Duration
}

// NewStoredSessionLoader creates a new storedSessionLoader which loads
// sessions from the session store.
// If no session is found, the request will be passed to the nex handler.
// If a session was loader by a previous handler, it will not be replaced.
func NewStoredSessionLoader(opts *StoredSessionLoaderOptions) alice.Constructor {
	ss := &storedSessionLoader{
		store:         opts.SessionStore,
		refreshPeriod: opts.RefreshPeriod,
	}
	return ss.loadSession
}

// storedSessionLoader is responsible for loading sessions from cookie
// identified sessions in the session store.
type storedSessionLoader struct {
	store         sessionsapi.SessionStore
	refreshPeriod time.Duration
}

// loadSession attempts to load a session as identified by the request cookies.
// If no session is found, the request will be passed to the next handler.
// If a session was loader by a previous handler, it will not be replaced.
func (s *storedSessionLoader) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)
		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		if scope.Session != nil {
			// The session was already loaded, pass to the next handler
			next.ServeHTTP(rw, req)
			return
		}

		var session *sessionsapi.SessionState
		provider := utils.ProviderFromContext(req.Context())
		if provider != nil {
			var err error
			session, err = s.getValidatedSession(rw, req, provider)
			if err != nil && !errors.Is(err, http.ErrNoCookie) {
				// In the case when there was an error loading the session,
				// we should clear the session
				logger.Errorf("Error loading cookied session: %v, removing session", err)
				err = s.store.Clear(rw, req)
				if err != nil {
					logger.Errorf("Error removing session: %v", err)
				}
			}
		}

		// Add the session to the scope if it was found
		scope.Session = session
		next.ServeHTTP(rw, req)
	})
}

// getValidatedSession is responsible for loading a session and making sure
// that is is valid.
func (s *storedSessionLoader) getValidatedSession(rw http.ResponseWriter, req *http.Request, provider providers.Provider) (*sessionsapi.SessionState, error) {
	session, err := s.store.Load(req)
	if err != nil || session == nil {
		// No session was found in the storage or error occurred, nothing more to do
		return nil, err
	}

	err = s.refreshSessionIfNeeded(rw, req, provider, session)
	if err != nil {
		return nil, fmt.Errorf("error refreshing access token for session (%s): %v", session, err)
	}

	return session, nil
}

// refreshSessionIfNeeded will attempt to refresh a session if the session
// is older than the refresh period.
// Success or fail, we will then validate the session.
func (s *storedSessionLoader) refreshSessionIfNeeded(rw http.ResponseWriter, req *http.Request, provider providers.Provider, session *sessionsapi.SessionState) error {
	if !needsRefresh(s.refreshPeriod, session) {
		// Refresh is disabled or the session is not old enough, do nothing
		return nil
	}

	var lockObtained bool
	ctx, cancel := context.WithTimeout(context.Background(), sessionRefreshObtainTimeout)
	defer cancel()

	for !lockObtained {
		select {
		case <-ctx.Done():
			return errors.New("timeout obtaining session lock")
		default:
			err := session.ObtainLock(req.Context(), sessionRefreshLockDuration)
			if err != nil && !errors.Is(err, sessionsapi.ErrLockNotObtained) {
				return fmt.Errorf("error occurred while trying to obtain lock: %v", err)
			} else if errors.Is(err, sessionsapi.ErrLockNotObtained) {
				time.Sleep(sessionRefreshRetryPeriod)
				continue
			}
			// No error means we obtained the lock
			lockObtained = true
		}
	}

	// The rest of this function is carried out under lock, but we must release it
	// wherever we exit from this function.
	defer func() {
		if session == nil {
			return
		}
		if err := session.ReleaseLock(req.Context()); err != nil {
			logger.Errorf("unable to release lock: %v", err)
		}
	}()

	// Reload the session in case it was changed underneath us.
	freshSession, err := s.store.Load(req)
	if err != nil {
		return fmt.Errorf("could not load session: %v", err)
	}
	if freshSession == nil {
		return errors.New("session no longer exists, it may have been removed by another request")
	}
	// Restore the state of the fresh session into the original pointer.
	// This is important so that changes are passed up the to the parent scope.
	lock := session.Lock
	*session = *freshSession

	// Ensure we maintain the session lock after we have refreshed the session.
	// Loading from the session store creates a new lock in the session.
	session.Lock = lock

	if !needsRefresh(s.refreshPeriod, session) {
		// The session must have already been refreshed while we were waiting to
		// obtain the lock.
		return nil
	}

	// We are holding the lock and the session needs a refresh
	logger.Printf("Refreshing session - User: %s; SessionAge: %s", session.User, session.Age())
	if err := s.refreshSession(rw, req, provider, session); err != nil {
		// If a preemptive refresh fails, we still keep the session
		// if validateSession succeeds.
		logger.Errorf("Unable to refresh session: %v", err)
	}

	// Validate all sessions after any Redeem/Refresh operation (fail or success)
	return s.validateSession(req.Context(), provider, session)
}

// needsRefresh determines whether we should attempt to refresh a session or not.
func needsRefresh(refreshPeriod time.Duration, session *sessionsapi.SessionState) bool {
	return refreshPeriod > time.Duration(0) && ((session.Age() > refreshPeriod) || session.IsExpired())
}

// refreshSession attempts to refresh the session with the provider
// and will save the session if it was updated.
func (s *storedSessionLoader) refreshSession(rw http.ResponseWriter, req *http.Request, provider providers.Provider, session *sessionsapi.SessionState) error {
	refreshed, err := provider.RefreshSession(req.Context(), session)
	if err != nil && !errors.Is(err, providers.ErrNotImplemented) {
		return fmt.Errorf("error refreshing tokens: %v", err)
	}

	// HACK:
	// Providers that don't implement `RefreshSession` use the default
	// implementation which returns `ErrNotImplemented`.
	// Pretend it refreshed to reset the refresh timer so that `ValidateSession`
	// isn't triggered every subsequent request and is only called once during
	// this request.
	if errors.Is(err, providers.ErrNotImplemented) {
		refreshed = true
	}

	// Session not refreshed, nothing to persist.
	if !refreshed {
		return nil
	}

	// If we refreshed, update the `CreatedAt` time to reset the refresh timer
	// (In case underlying provider implementations forget)
	session.CreatedAtNow()

	// Because the session was refreshed, make sure to save it
	err = s.store.Save(rw, req, session)
	if err != nil {
		logger.PrintAuthf(session.Email, req, logger.AuthError, "error saving session: %v", err)
		return fmt.Errorf("error saving session: %v", err)
	}
	return nil
}

// validateSession checks whether the session has expired and performs
// provider validation on the session.
// An error implies the session is not longer valid.
func (s *storedSessionLoader) validateSession(ctx context.Context, provider providers.Provider, session *sessionsapi.SessionState) error {
	if session.IsExpired() {
		return errors.New("session is expired")
	}

	if !provider.ValidateSession(ctx, session) {
		return errors.New("session is invalid")
	}

	return nil
}
