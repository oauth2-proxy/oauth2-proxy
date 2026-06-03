package persistence

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// Manager wraps a Store and handles the implementation details of the
// sessions.SessionStore with its use of session tickets
type Manager struct {
	Store   Store
	Options *options.Cookie
}

// NewManager creates a Manager that can wrap a Store and manage the
// sessions.SessionStore implementation details
func NewManager(store Store, cookieOpts *options.Cookie) *Manager {
	return &Manager{
		Store:   store,
		Options: cookieOpts,
	}
}

// sidIndexKey returns the Redis key that maps an OIDC session ID (sid claim)
// to a session ticket ID, enabling back-channel logout lookups.
func (m *Manager) sidIndexKey(sessionID string) string {
	return m.Options.Name + "-sid-" + sessionID
}

// ClearBySID removes the session identified by the given OIDC session ID.
// Called during OIDC back-channel logout. Implements BackChannelSessionStore.
func (m *Manager) ClearBySID(ctx context.Context, sessionID string) error {
	sidKey := m.sidIndexKey(sessionID)

	ticketIDBytes, err := m.Store.Load(ctx, sidKey)
	if err != nil {
		return fmt.Errorf("no session found for sid %q: %w", sessionID, err)
	}

	if err := m.Store.Clear(ctx, string(ticketIDBytes)); err != nil {
		return fmt.Errorf("failed to clear session for sid %q: %w", sessionID, err)
	}

	if err := m.Store.Clear(ctx, sidKey); err != nil {
		logger.Errorf("failed to clear SID index for %q (non-fatal): %v", sessionID, err)
	}

	return nil
}

// Save saves a session in a persistent Store. Save will generate (or reuse an
// existing) ticket which manages unique per session encryption & retrieval
// from the persistent data store.
func (m *Manager) Save(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) error {
	if s.CreatedAt == nil || s.CreatedAt.IsZero() {
		s.CreatedAtNow()
	}

	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		tckt, err = newTicket(m.Options)
		if err != nil {
			return fmt.Errorf("error creating a session ticket: %v", err)
		}
	}

	err = tckt.saveSession(s, func(key string, val []byte, exp time.Duration) error {
		return m.Store.Save(req.Context(), key, val, exp)
	})
	if err != nil {
		return err
	}

	// Secondary index: sid → ticketID, for back-channel logout
	if s.SessionID != "" {
		sidKey := m.sidIndexKey(s.SessionID)
		if err := m.Store.Save(req.Context(), sidKey, []byte(tckt.id), m.Options.Expire); err != nil {
			logger.Errorf("failed to save SID index for back-channel logout: %v", err)
		}
	}

	return tckt.setCookie(rw, req, s)
}

// Load reads sessions.SessionState information from a session store. It will
// use the session ticket from the http.Request's cookie.
func (m *Manager) Load(req *http.Request) (*sessions.SessionState, error) {
	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		return nil, err
	}

	return tckt.loadSession(
		func(key string) ([]byte, error) {
			return m.Store.Load(req.Context(), key)
		},
		m.Store.Lock,
	)
}

// Clear clears any saved session information for a given ticket cookie.
// Then it clears all session data for that ticket in the Store.
func (m *Manager) Clear(rw http.ResponseWriter, req *http.Request) error {
	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		// Always clear the cookie, even when we can't load a cookie from
		// the request
		tckt = &ticket{
			options: m.Options,
		}
		tckt.clearCookie(rw, req)
		// Don't raise an error if we didn't have a Cookie
		if err == http.ErrNoCookie {
			return nil
		}
		return fmt.Errorf("error decoding ticket to clear session: %v", err)
	}

	tckt.clearCookie(rw, req)
	return tckt.clearSession(func(key string) error {
		return m.Store.Clear(req.Context(), key)
	})
}

// VerifyConnection validates the underlying store is ready and connected
func (m *Manager) VerifyConnection(ctx context.Context) error {
	return m.Store.VerifyConnection(ctx)
}
