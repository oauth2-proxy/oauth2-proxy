package persistence

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
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

// Create creates a session in a persistent Store. Create will generate (or reuse an
// existing) ticket which manages unique per session encryption & retrieval
// from the persistent data store.
func (m *Manager) Create(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) error {
	if s.CreatedAt == nil || s.CreatedAt.IsZero() {
		s.CreatedAtNow()
	}

	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		retry := 0
		for {
			tckt, err = newTicket(m.Options)
			if err != nil {
				return fmt.Errorf("error creating a session ticket: %v", err)
			}

			err = tckt.saveSession(s, func(key string, val []byte, exp time.Duration) error {
				return m.Store.Create(req.Context(), key, val, exp)
			})
			if err != nil {
				// Retry creating a session if it returns duplicate session key error
				// since it should generate non-duplicate key next time
				if errors.Is(err, sessions.ErrDuplicateSessionKey) && retry < 1 {
					retry++
					continue
				}
				return err
			}
			return tckt.setCookie(rw, req, s)
		}
	} else {
		err = tckt.saveSession(s, func(key string, val []byte, exp time.Duration) error {
			return m.Store.CreateOrUpdate(req.Context(), key, val, exp)
		})
		if err != nil {
			return err
		}
		return tckt.setCookie(rw, req, s)
	}
}

// Update saves a session existing in a persistent Store. Update will reuse an
// existing ticket which manages unique per session encryption & retrieval
// from the persistent data store.
func (m *Manager) Update(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) error {
	if s.CreatedAt == nil || s.CreatedAt.IsZero() {
		s.CreatedAtNow()
	}

	tckt, err := decodeTicketFromRequest(req, m.Options)
	if err != nil {
		return fmt.Errorf("error decoding ticket to update session: %v", err)
	}

	err = tckt.saveSession(s, func(key string, val []byte, exp time.Duration) error {
		return m.Store.Update(req.Context(), key, val, exp)
	})
	if err != nil {
		return err
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
