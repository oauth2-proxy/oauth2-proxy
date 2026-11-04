package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

const (
	// Maximum time allowed for the critical section of a session refresh:
	// reloading the session, redeeming the refresh token with the provider and
	// persisting the result. It is independent of the triggering request, so a
	// client disconnect cannot interrupt a refresh after the provider may
	// already have rotated the refresh token.
	// TODO: This should probably be configurable by the end user.
	sessionRefreshTimeout = 30 * time.Second

	// Margin added to sessionRefreshTimeout for the lifetime of the session
	// refresh lock, so the lock outlives the critical section it protects. It
	// also bounds how long releasing the lock may take.
	// TODO: This should probably be configurable by the end user.
	sessionRefreshLockDuration = 2 * time.Second

	// How long to wait after failing to obtain the lock before trying again.
	// TODO: This should probably be configurable by the end user.
	sessionRefreshRetryPeriod = 10 * time.Millisecond
)

// isFatalRefreshError checks if a refresh error indicates a revoked or
// non-existent session that should be immediately invalidated.
// Fatal errors indicate the session is no longer valid at the provider level.
// Non-fatal errors (network issues, timeouts) should not invalidate the session.
//
// Only checks standard OAuth2 error codes (RFC 6749 Section 5.2).
// Does NOT check error_description strings as they are optional and provider-specific.
func isFatalRefreshError(err error) bool {
	if err == nil {
		return false
	}

	// Only check standard OAuth2 error codes (RFC 6749 Section 5.2)
	// Do NOT check error_description strings as they are optional and provider-specific
	fatalErrors := []string{
		"invalid_grant",  // refresh token revoked, expired, or session terminated
		"invalid_client", // client credentials no longer valid
	}

	for _, fe := range fatalErrors {
		if strings.Contains(err.Error(), fe) {
			return true
		}
	}
	return false
}

// StoredSessionLoaderOptions contains all of the requirements to construct
// a stored session loader.
// All options must be provided.
type StoredSessionLoaderOptions struct {
	// Session storage backend
	SessionStore sessionsapi.SessionStore

	// How often should sessions be refreshed
	RefreshPeriod time.Duration

	// Provider based session refreshing
	RefreshSession func(context.Context, *sessionsapi.SessionState) (bool, error)

	// Provider based session validation.
	// If the sesssion is older than `RefreshPeriod` but the provider doesn't
	// refresh it, we must re-validate using this validation.
	ValidateSession func(context.Context, *sessionsapi.SessionState) bool
}

// NewStoredSessionLoader creates a new storedSessionLoader which loads
// sessions from the session store.
// If no session is found, the request will be passed to the nex handler.
// If a session was loader by a previous handler, it will not be replaced.
func NewStoredSessionLoader(opts *StoredSessionLoaderOptions) alice.Constructor {
	ss := &storedSessionLoader{
		store:            opts.SessionStore,
		refreshPeriod:    opts.RefreshPeriod,
		sessionRefresher: opts.RefreshSession,
		sessionValidator: opts.ValidateSession,
	}
	return ss.loadSession
}

// storedSessionLoader is responsible for loading sessions from cookie
// identified sessions in the session store.
type storedSessionLoader struct {
	store            sessionsapi.SessionStore
	refreshPeriod    time.Duration
	sessionRefresher func(context.Context, *sessionsapi.SessionState) (bool, error)
	sessionValidator func(context.Context, *sessionsapi.SessionState) bool

	// Overrides for sessionRefreshTimeout and sessionRefreshLockDuration.
	// Zero means the default; only tests set them.
	refreshTimeout      time.Duration
	refreshLockDuration time.Duration
}

func (s *storedSessionLoader) getRefreshTimeout() time.Duration {
	if s.refreshTimeout > 0 {
		return s.refreshTimeout
	}
	return sessionRefreshTimeout
}

func (s *storedSessionLoader) getRefreshLockDuration() time.Duration {
	if s.refreshLockDuration > 0 {
		return s.refreshLockDuration
	}
	return sessionRefreshLockDuration
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
		if err != nil && !errors.Is(err, http.ErrNoCookie) {
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
// that it is valid.
func (s *storedSessionLoader) getValidatedSession(rw http.ResponseWriter, req *http.Request) (*sessionsapi.SessionState, error) {
	session, err := s.store.Load(req)
	if err != nil || session == nil {
		// No session was found in the storage or error occurred, nothing more to do
		return nil, err
	}

	err = s.refreshSessionIfNeeded(rw, req, session)
	if err != nil {
		return nil, fmt.Errorf("error refreshing access token for session (%s): %v", session, err)
	}

	return session, nil
}

// refreshSessionIfNeeded will attempt to refresh a session if the session
// is older than the refresh period.
// Success or fail, we will then validate the session.
func (s *storedSessionLoader) refreshSessionIfNeeded(rw http.ResponseWriter, req *http.Request, session *sessionsapi.SessionState) error {
	if !needsRefresh(s.refreshPeriod, session) {
		// Refresh is disabled or the session is not old enough, do nothing
		return nil
	}

	refreshTimeout := s.getRefreshTimeout()
	lockMargin := s.getRefreshLockDuration()

	// The lock lives for the whole bounded critical section plus a margin, so
	// it cannot expire while the holder is still able to redeem or persist the
	// refresh token, however slow the provider is or however long Redis is
	// unreachable. If the holder dies, the lock expires on its own.
	lockTTL := refreshTimeout + lockMargin

	// Wait for at least as long as another request may hold the lock, so that
	// this request picks up the refreshed tokens, or obtains the lock once a
	// holder that died has let it expire. Stop waiting if the client goes away;
	// nothing has been redeemed yet.
	waitCtx, cancelWait := context.WithTimeout(req.Context(), lockTTL+lockMargin)
	defer cancelWait()

	if err := obtainLock(waitCtx, session, lockTTL); err != nil {
		if req.Context().Err() != nil {
			return err
		}
		// Another request is still refreshing, or Redis is briefly
		// unavailable. Neither makes this session invalid, and clearing it
		// would also remove the session the other request is refreshing, so
		// keep it as for any non-fatal refresh failure.
		logger.Errorf("Not refreshing session - User: %s: %v", session.User, err)
		return s.validateSession(req.Context(), session)
	}

	// From here on the provider may rotate the refresh token, so the work must
	// not depend on the triggering request staying alive: a cancelled request
	// would otherwise abort the redeem or the save of the rotated token and the
	// next request would present the old, already redeemed, refresh token.
	// The detached context is still bounded by refreshTimeout, which the lock
	// lifetime covers.
	refreshCtx, cancelRefresh := context.WithTimeout(context.WithoutCancel(req.Context()), refreshTimeout)
	defer cancelRefresh()
	refreshReq := req.WithContext(refreshCtx)

	// Loading from the session store creates a new lock in the session, so
	// keep a reference to the lock we hold.
	lock := session.Lock

	// The rest of this function is carried out under lock, but we must release it
	// wherever we exit from this function. The release only removes a lock that
	// is still ours, and uses its own context so that it still happens after a
	// cancelled request or a timed out refresh.
	defer func() {
		releaseCtx, cancelRelease := context.WithTimeout(context.WithoutCancel(req.Context()), lockMargin)
		defer cancelRelease()
		if err := lock.Release(releaseCtx); err != nil {
			logger.Errorf("unable to release lock: %v", err)
		}
	}()

	// Reload the session in case it was changed underneath us.
	freshSession, err := s.store.Load(refreshReq)
	if err != nil {
		return fmt.Errorf("could not load session: %v", err)
	}
	if freshSession == nil {
		return errors.New("session no longer exists, it may have been removed by another request")
	}
	// Restore the state of the fresh session into the original pointer.
	// This is important so that changes are passed up the to the parent scope.
	*session = *freshSession

	// Ensure we maintain the session lock after we have refreshed the session.
	// Loading from the session store creates a new lock in the session.
	session.Lock = lock

	if !needsRefresh(s.refreshPeriod, session) {
		// The session must have already been refreshed while we were waiting to
		// obtain the lock.
		return nil
	}

	// Presenting the refresh token cannot be undone, so right before doing it,
	// confirm that we still own the lock and extend it to cover the rest of the
	// refresh. If the lock is gone (e.g. Redis lost the key) another request
	// may be redeeming the same token, and if Redis is unreachable a rotated
	// token could not be saved; either way, keep the current session as for
	// any non-fatal refresh failure.
	if err := extendLock(refreshCtx, lock, lockMargin); err != nil {
		logger.Errorf("Not refreshing session, could not confirm the session refresh lock - User: %s: %v", session.User, err)
		return s.validateSession(req.Context(), session)
	}

	// We are holding the lock and the session needs a refresh
	logger.Printf("Refreshing session - User: %s; SessionAge: %s", session.User, session.Age())
	if err := s.refreshSession(rw, refreshReq, session); err != nil {
		logger.Errorf("Unable to refresh session: %v", err)

		// Check if this is a fatal error that indicates the session is revoked
		// or no longer valid at the provider level
		if isFatalRefreshError(err) {
			logger.Printf("Fatal refresh error detected (session revoked or invalid), clearing session for user: %s", session.User)

			// Clear the session from storage (Redis) and remove the cookie
			if err := s.store.Clear(rw, refreshReq); err != nil {
				logger.Errorf("failed clearing session: %v", err)
			}

			// Return error immediately to force re-authentication
			return fmt.Errorf("session invalidated due to fatal refresh error: %w", err)
		}

		// For non-fatal errors (network issues, timeouts), keep the session
		// and let validateSession determine if it's still usable
	}

	// Validate all sessions after any Redeem/Refresh operation (fail or success)
	return s.validateSession(req.Context(), session)
}

// obtainLock retries obtaining the session refresh lock, for ttl, until it
// succeeds or ctx is done.
func obtainLock(ctx context.Context, session *sessionsapi.SessionState, ttl time.Duration) error {
	for {
		err := session.ObtainLock(ctx, ttl)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return lockWaitError(ctx)
		}
		if !errors.Is(err, sessionsapi.ErrLockNotObtained) {
			return fmt.Errorf("error occurred while trying to obtain lock: %v", err)
		}

		retry := time.NewTimer(sessionRefreshRetryPeriod)
		select {
		case <-ctx.Done():
			retry.Stop()
			return lockWaitError(ctx)
		case <-retry.C:
		}
	}
}

func lockWaitError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return errors.New("timeout obtaining session lock")
	}
	return fmt.Errorf("stopped waiting for session lock: %w", ctx.Err())
}

// extendLock confirms that the session refresh lock is still held and extends
// it to the deadline of ctx plus margin. The lock implementation only extends
// a lock that is still ours, and reports ErrNotLocked otherwise.
func extendLock(ctx context.Context, lock sessionsapi.Lock, margin time.Duration) error {
	ttl := margin
	if deadline, ok := ctx.Deadline(); ok {
		ttl += time.Until(deadline)
	}
	err := lock.Refresh(ctx, ttl)
	if errors.Is(err, sessionsapi.ErrNotLocked) {
		return fmt.Errorf("session refresh lock is no longer held: %w", err)
	}
	return err
}

// needsRefresh determines whether we should attempt to refresh a session or not.
func needsRefresh(refreshPeriod time.Duration, session *sessionsapi.SessionState) bool {
	return refreshPeriod > time.Duration(0) && session.Age() > refreshPeriod
}

// refreshSession attempts to refresh the session with the provider
// and will save the session if it was updated.
func (s *storedSessionLoader) refreshSession(rw http.ResponseWriter, req *http.Request, session *sessionsapi.SessionState) error {
	refreshed, err := s.sessionRefresher(req.Context(), session)
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
		logger.Printf("Session not refreshed - User: %s; no refresh token available or provider returned false", session.User)
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
func (s *storedSessionLoader) validateSession(ctx context.Context, session *sessionsapi.SessionState) error {
	if session.IsExpired() {
		return errors.New("session is expired")
	}

	if !s.sessionValidator(ctx, session) {
		return errors.New("session is invalid")
	}

	return nil
}
