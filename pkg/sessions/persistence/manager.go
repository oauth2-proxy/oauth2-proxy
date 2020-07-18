package persistence

import (
	"fmt"
	"net/http"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
)

// Manager holds the ResponseWriter, Request & Cookie Options used by the
// Save, Load & Clear helper methods
type Manager struct {
	Store   Store
	Options *options.Cookie
}

// NewManager creates a light wrapper around HTTP request & response and cookie
// options for use by the Save, Load & Clear helper methods
func NewManager(store Store, cookieOpts *options.Cookie) *Manager {
	return &Manager{
		Store:   store,
		Options: cookieOpts,
	}
}

// Save takes a sessions.SessionState and stores the encoded version of it
// using the passed in SaveFunc. Save will generate (or reuse an existing)
// Ticker which manages unique per session encryption & retrieval from the
// persistent data store.
func (m *Manager) Save(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) error {
	if s.CreatedAt == nil || s.CreatedAt.IsZero() {
		now := time.Now()
		s.CreatedAt = &now
	}

	ticket, err := DecodeTicketFromRequest(req, m.Options)
	if err != nil {
		ticket, err = NewTicket(m.Options)
		if err != nil {
			return fmt.Errorf("error creating a session ticket: %v", err)
		}
	}
	err = ticket.SaveSession(s, func(key string, val []byte, exp time.Duration) error {
		return m.Store.Save(req.Context(), key, val, exp)
	})
	if err != nil {
		return err
	}
	ticket.SetCookie(rw, req, s)

	return nil
}

// Load reads sessions.SessionState information from a session store
// using the LoadFunc & Ticket details in the session cookie.
func (m *Manager) Load(req *http.Request) (*sessions.SessionState, error) {
	ticket, err := DecodeTicketFromRequest(req, m.Options)
	if err != nil {
		return nil, err
	}

	return ticket.LoadSession(func(key string) ([]byte, error) {
		return m.Store.Load(req.Context(), key)
	})
}

// Clear clears any saved session information for a given ticket cookie.
// Then it clears all session data for that ticket in the store using
// the passed ClearFunc
func (m *Manager) Clear(rw http.ResponseWriter, req *http.Request) error {
	ticket, err := DecodeTicketFromRequest(req, m.Options)
	if err != nil {
		// Always clear the cookie, even when we can't load a cookie from
		// the request
		ticket = &Ticket{
			Options: m.Options,
		}
		ticket.ClearCookie(rw, req)
		// Don't raise an error if we didn't have a Cookie
		if err == http.ErrNoCookie {
			return nil
		}
		return fmt.Errorf("error decoding ticket to clear session: %v", err)
	}

	ticket.ClearCookie(rw, req)
	return ticket.ClearSession(func(key string) error {
		return m.Store.Clear(req.Context(), key)
	})
}
