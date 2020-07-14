package persistence

import (
	"fmt"
	"net/http"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
)

// SaveFunc performs a persistent store's save functionality using
// a key string, value []byte & (optional) expiration time.Duration
type SaveFunc func(string, []byte, time.Duration) error

// LoadFunc performs a load from a persistent store using a
// string key and returning the stored value as []byte
type LoadFunc func(string) ([]byte, error)

// ClearFunc performs a persistent store's clear functionality using
// a string key for the target of the deletion.
type ClearFunc func(string) error

// Manager holds the ResponseWriter, Request & Cookie Options used by the
// Save, Load & Clear helper methods
type Manager struct {
	ResponseWriter http.ResponseWriter
	Request        *http.Request
	Options        *options.Cookie
}

// NewManager creates a light wrapper around HTTP request & response and cookie
// options for use by the Save, Load & Clear helper methods
func NewManager(rw http.ResponseWriter, req *http.Request, cookieOpts *options.Cookie) *Manager {
	return &Manager{
		ResponseWriter: rw,
		Request:        req,
		Options:        cookieOpts,
	}
}

// Save takes a sessions.SessionState and stores the encoded version of it
// using the passed in SaveFunc. Save will generate (or reuse an existing)
// Ticker which manages unique per session encryption & retrieval from the
// persistent data store.
func (m *Manager) Save(s *sessions.SessionState, saver SaveFunc) error {
	if s.CreatedAt == nil || s.CreatedAt.IsZero() {
		now := time.Now()
		s.CreatedAt = &now
	}

	ticket, err := DecodeTicketFromRequest(m.Request, m.Options)
	if err != nil {
		ticket, err = NewTicket(m.Options)
		if err != nil {
			return fmt.Errorf("error creating a session ticket: %v", err)
		}
	}
	err = ticket.SaveSession(s, saver)
	if err != nil {
		return fmt.Errorf("error saving redis session: %v", err)
	}
	ticket.SetCookie(m.ResponseWriter, m.Request, s)

	return nil
}

// Load reads sessions.SessionState information from a session store
// using the LoadFunc & Ticket details in the session cookie.
func (m *Manager) Load(loader LoadFunc) (*sessions.SessionState, error) {
	ticket, err := DecodeTicketFromRequest(m.Request, m.Options)
	if err != nil {
		return nil, fmt.Errorf("error loading session: %v", err)
	}

	return ticket.LoadSession(loader)
}

// Clear clears any saved session information for a given ticket cookie.
// Then it clears all session data for that ticket in the store using
// the passed ClearFunc
func (m *Manager) Clear(clearer ClearFunc) error {
	ticket, err := DecodeTicketFromRequest(m.Request, m.Options)
	if err != nil {
		// Always clear the cookie, even when we can't load a cookie from
		// the request
		ticket = &Ticket{
			Options: m.Options,
		}
		ticket.ClearCookie(m.ResponseWriter, m.Request)
		// Don't raise an error if we didn't have a Cookie
		if err == http.ErrNoCookie {
			return nil
		}
		return fmt.Errorf("error decoding ticket to clear redis session: %v", err)
	}

	ticket.ClearCookie(m.ResponseWriter, m.Request)
	err = ticket.ClearSession(clearer)
	if err != nil {
		return fmt.Errorf("error clearing the session from redis: %v", err)
	}
	return nil
}
