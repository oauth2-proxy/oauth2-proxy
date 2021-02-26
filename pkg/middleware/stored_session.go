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
)

// StoredSessionLoaderOptions cotnains all of the requirements to construct
// a stored session loader.
// All options must be provided.
type StoredSessionLoaderOptions struct {
	// Session storage basckend
	SessionStore sessionsapi.SessionStore

	// How often should sessions be refreshed
	RefreshPeriod time.Duration

	// Provider based sesssion refreshing
	RefreshSession func(context.Context, *sessionsapi.SessionState) (bool, error)

	// Provider based session refresh check
	IsRefreshNeeded func(*sessionsapi.SessionState) bool

	// Provider based session validation.
	// If the session is older than `RefreshPeriod` but the provider doesn't
	// refresh it, we must re-validate using this validation.
	ValidateSessionState func(context.Context, *sessionsapi.SessionState) bool
}

// NewStoredSessionLoader creates a new storedSessionLoader which loads
// sessions from the session store.
// If no session is found, the request will be passed to the nex handler.
// If a session was loader by a previous handler, it will not be replaced.
func NewStoredSessionLoader(opts *StoredSessionLoaderOptions) alice.Constructor {
	ss := &storedSessionLoader{
		store:                       opts.SessionStore,
		refreshPeriod:               opts.RefreshPeriod,
		refreshSessionWithProvider:  opts.RefreshSession,
		isRefreshNeededWithProvider: opts.IsRefreshNeeded,
		validateSessionState:        opts.ValidateSessionState,
	}
	return ss.loadSession
}

// storedSessionLoader is responsible for loading sessions from cookie
// identified sessions in the session store.
type storedSessionLoader struct {
	store                       sessionsapi.SessionStore
	refreshPeriod               time.Duration
	refreshSessionWithProvider  func(context.Context, *sessionsapi.SessionState) (bool, error)
	isRefreshNeededWithProvider func(*sessionsapi.SessionState) bool
	validateSessionState        func(context.Context, *sessionsapi.SessionState) bool
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

		session, err := s.getValidatedSession(rw, req)
		if err != nil {
			// In the case when there was an error loading the session,
			// we should clear the session
			logger.Errorf("Error loading cookied session: %v, removing session", err)
			err = s.store.Clear(rw, req)
			if err != nil {
				logger.Errorf("Error removing session: %v", err)
			}
		}

		// Add the session to the scope if it was found
		scope.Session = session
		next.ServeHTTP(rw, req)
	})
}

// getValidatedSession is responsible for loading a session and making sure
// that is is valid.
func (s *storedSessionLoader) getValidatedSession(rw http.ResponseWriter, req *http.Request) (*sessionsapi.SessionState, error) {
	session, err := s.loadRefreshedSession(req, 1)
	if err != nil {
		return nil, err
	}
	if session != nil {
		return session, nil
	}

	session, err = s.store.LoadWithLock(req)
	if err != nil {
		return s.loadRefreshedSession(req, 10)
	}
	defer s.store.ReleaseLock(req)
	if session == nil {
		// No session was found in the storage, nothing more to do
		return nil, nil
	}

	if !s.isSessionRefreshNeeded(session) {
		return session, nil
	}
	logger.Printf("Refreshing %s old session cookie for %s (refresh after %s)", session.Age(), session, s.refreshPeriod)
	refreshed, err := s.refreshSession(rw, req, session)
	if err != nil {
		return nil, fmt.Errorf("error refreshing access token for session (%s): %v", session, err)
	}

	if refreshed {
		return session, nil
	}

	// Session wasn't refreshed, so make sure it's still valid
	err = s.validateSession(req.Context(), session)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (s *storedSessionLoader) loadRefreshedSession(req *http.Request, maxAttempts int) (*sessionsapi.SessionState, error) {
	for i := 0; i < maxAttempts; i++ {
		session, err := s.store.Load(req)
		if err != nil {
			return nil, err
		}
		if session == nil {
			// No session was found in the storage, nothing more to do
			return nil, nil
		}

		if !s.isSessionRefreshNeeded(session) {
			return session, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, nil
}

// isSessionRefreshNeeded will check if the session need to be refreshed
func (s *storedSessionLoader) isSessionRefreshNeeded(session *sessionsapi.SessionState) bool {
	if s.refreshPeriod > time.Duration(0) && session.Age() >= s.refreshPeriod {
		return s.isRefreshNeededWithProvider(session)
	}
	return false
}

// refreshSession attempts to refresh the sessinon with the provider
// and will save the session if it was updated.
func (s *storedSessionLoader) refreshSession(rw http.ResponseWriter, req *http.Request, session *sessionsapi.SessionState) (bool, error) {
	refreshed, err := s.refreshSessionWithProvider(req.Context(), session)
	if err != nil {
		return false, fmt.Errorf("error refreshing access token: %v", err)
	}

	if !refreshed {
		return false, nil
	}

	// Because the session was refreshed, make sure to save it
	err = s.store.Save(rw, req, session)
	if err != nil {
		logger.PrintAuthf(session.Email, req, logger.AuthError, "error saving session: %v", err)
		return false, fmt.Errorf("error saving session: %v", err)
	}
	return true, nil
}

// validateSession checks whether the session has expired and performs
// provider validation on the session.
// An error implies the session is not longer valid.
func (s *storedSessionLoader) validateSession(ctx context.Context, session *sessionsapi.SessionState) error {
	if session.IsExpired() {
		return errors.New("session is expired")
	}

	if !s.validateSessionState(ctx, session) {
		return errors.New("session is invalid")
	}

	return nil
}
