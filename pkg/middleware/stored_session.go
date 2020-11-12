package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/justinas/alice"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// StoredSessionLoaderOptions cotnains all of the requirements to construct
// a stored session loader.
// All options must be provided.
type StoredSessionLoaderOptions struct {
	// Session storage basckend
	SessionStore sessionsapi.SessionStore

	// Whether sessions should be refreshed
	Refresh bool

	// What percentage of the token expiry period to refresh by
	RefreshPercent uint8

	// Provider based sesssion refreshing
	RefreshSession func(context.Context, *sessionsapi.SessionState) error

	// Provider based session validation.
	// If the sesssion is older than `RefreshPeriod` but the provider doesn't
	// refresh it, we must re-validate using this validation.
	ValidateSessionState func(context.Context, *sessionsapi.SessionState) bool
}

// NewStoredSessionLoader creates a new storedSessionLoader which loads
// sessions from the session store.
// If no session is found, the request will be passed to the nex handler.
// If a session was loader by a previous handler, it will not be replaced.
func NewStoredSessionLoader(opts *StoredSessionLoaderOptions) alice.Constructor {
	ss := &storedSessionLoader{
		store:                opts.SessionStore,
		refresh:              opts.Refresh,
		refreshPercent:       opts.RefreshPercent,
		refreshSession:       opts.RefreshSession,
		validateSessionState: opts.ValidateSessionState,
	}
	return ss.loadSession
}

// storedSessionLoader is responsible for loading sessions from cookie
// identified sessions in the session store.
type storedSessionLoader struct {
	store                sessionsapi.SessionStore
	refresh              bool
	refreshPercent       uint8
	refreshSession       func(context.Context, *sessionsapi.SessionState) error
	validateSessionState func(context.Context, *sessionsapi.SessionState) bool
}

// loadSession attempts to load a session as identified by the request cookies.
// If no session is found, the request will be passed to the next handler.
// If a session was loader by a previous handler, it will not be replaced.
func (s *storedSessionLoader) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := GetRequestScope(req)
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
	session, err := s.store.Load(req)
	if err != nil {
		return nil, err
	}
	if session == nil {
		// No session was found in the storage, nothing more to do
		return nil, nil
	}

	err = s.refreshSessionIfNeeded(rw, req, session)
	if err != nil {
		return nil, fmt.Errorf("error refreshing access token for session (%s): %v", session, err)
	}

	return session, nil
}

// refreshSessionIfNeeded will attempt to refresh a session
// It is assumed that if the provider refreshes the session, the session is now
// valid.
// If the session requires refreshing but the provider does not refresh it,
// we must validate the session to ensure that the returned session is still
// valid.
func (s *storedSessionLoader) refreshSessionIfNeeded(rw http.ResponseWriter, req *http.Request, session *sessionsapi.SessionState) error {
	if !s.refresh || session == nil {
		// Refresh is disabled or there is no session, do nothing
		return nil
	}

	if session.ExpiresOn != nil && session.ExpiresOn.After(time.Now()) || session.RefreshToken == "" {
		// Session is blank, has not yet expired or cannot be refreshed due to absent refresh token
		// Validate existing session
		return s.validateSession(req.Context(), session)
	}

	logger.Printf("Refreshing %s old session cookie for %s", session.Age(), session)
	return s.refreshSessionWithProvider(rw, req, session)
}

// refreshSessionWithProvider attempts to refresh the sessinon with the provider
// and will save the session if it was updated.
func (s *storedSessionLoader) refreshSessionWithProvider(rw http.ResponseWriter, req *http.Request, session *sessionsapi.SessionState) error {
	err := s.refreshSession(req.Context(), session)
	if err != nil {
		return fmt.Errorf("error refreshing access token: %v", err)
	}

	// Recalculate expiration based on refresh percentage
	originalExpiresOn := session.AdjustExpirationByRefreshPercent(s.refreshPercent)

	logger.Printf("session created on %s, expires on %s, refresh starting on %s", session.CreatedAt, originalExpiresOn, session.ExpiresOn)

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
func (s *storedSessionLoader) validateSession(ctx context.Context, session *sessionsapi.SessionState) error {
	if session.IsExpired() {
		return errors.New("session is expired")
	}

	if !s.validateSessionState(ctx, session) {
		return errors.New("session is invalid")
	}

	return nil
}
