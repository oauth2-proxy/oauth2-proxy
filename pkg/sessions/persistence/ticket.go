package persistence

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/cookies"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
)

// saveFunc performs a persistent store's save functionality using
// a key string, value []byte & (optional) expiration time.Duration
type saveFunc func(string, []byte, time.Duration) error

// loadFunc performs a load from a persistent store using a
// string key and returning the stored value as []byte
type loadFunc func(string) ([]byte, error)

// clearFunc performs a persistent store's clear functionality using
// a string key for the target of the deletion.
type clearFunc func(string) error

// initLockFunc returns a lock object for a persistent store using a
// string key
type initLockFunc func(string) sessions.Lock

// ticket is a structure representing the ticket used in server based
// session storage. It provides a unique per session decryption secret giving
// more security than the shared CookieSecret.
type ticket struct {
	id      string
	secret  []byte
	options *options.Cookie
}

// newTicket creates a new ticket. The ID & secret will be randomly created
// with 16 byte sizes. The ID will be prefixed & hex encoded.
func newTicket(cookieOpts *options.Cookie) (*ticket, error) {
	rawID := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, rawID); err != nil {
		return nil, fmt.Errorf("failed to create new ticket ID: %v", err)
	}
	// ticketID is hex encoded
	ticketID := fmt.Sprintf("%s-%s", cookieOpts.Name, hex.EncodeToString(rawID))

	secret := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return nil, fmt.Errorf("failed to create encryption secret: %v", err)
	}

	return &ticket{
		id:      ticketID,
		secret:  secret,
		options: cookieOpts,
	}, nil
}

// encodeTicket encodes the Ticket to a string for usage in cookies
func (t *ticket) encodeTicket() string {
	return fmt.Sprintf("v2.%s.%s", base64.RawURLEncoding.EncodeToString([]byte(t.id)),
		base64.RawURLEncoding.EncodeToString(t.secret))
}

// decodeTicketID Tickets are encoded with format: {encoding version}.{ticketID base64}.{ticketSecret base 64}.
// Tickets from old oauth2-proxy versions do not have the same format, and this method tries
// to decode the ticket ID part based on the encoding version, or lack of it.
func decodeTicketID(ticketParts []string) (string, error) {
	switch {
	case len(ticketParts) == 2:
		// old ticket encoding
		return ticketParts[0], nil
	case len(ticketParts) == 3 && ticketParts[0] == "v2":
		// v2 ticket encoding
		ticketID, err := base64.RawURLEncoding.DecodeString(ticketParts[1])
		if err != nil {
			return "", fmt.Errorf("failed to decode ticket Id: %v", err)
		}
		return string(ticketID), nil
	default:
		return "", errors.New("failed to decode ticket Id")
	}
}

// decodeTicketSecret Tickets are encoded with format: {encoding version}.{ticketID base64}.{ticketSecret base 64}.
// Tickets from old oauth2-proxy versions do not have the same format, and this method tries
// to decode the ticket secret part based on the encoding version, or lack of it.
func decodeTicketSecret(ticketParts []string) ([]byte, error) {
	switch {
	case len(ticketParts) == 2:
		// old ticket encoding
		secret, err := base64.RawURLEncoding.DecodeString(ticketParts[1])
		if err != nil {
			return nil, fmt.Errorf("failed to decode encryption secret: %v", err)
		}
		return secret, nil
	case len(ticketParts) == 3 && ticketParts[0] == "v2":
		// new ticket encode
		secret, err := base64.RawURLEncoding.DecodeString(ticketParts[2])
		if err != nil {
			return nil, fmt.Errorf("failed to decode encryption secret: %v", err)
		}
		return secret, nil
	default:
		return nil, errors.New("failed to decode encryption secret")
	}
}

// decodeTicket decodes an encoded ticket string
func decodeTicket(encTicket string, cookieOpts *options.Cookie) (*ticket, error) {
	ticketParts := strings.Split(encTicket, ".")
	if len(ticketParts) != 2 && len(ticketParts) != 3 {
		return nil, errors.New("failed to decode ticket")
	}
	ticketID, errTicketID := decodeTicketID(ticketParts)
	if errTicketID != nil {
		return nil, fmt.Errorf("failed to decode ticket: %v", errTicketID)
	}
	secret, errSecret := decodeTicketSecret(ticketParts)
	if errSecret != nil {
		return nil, fmt.Errorf("failed to decode ticket: %v", errSecret)
	}
	return &ticket{
		id:      ticketID,
		secret:  secret,
		options: cookieOpts,
	}, nil
}

// decodeTicketFromRequest retrieves a potential ticket cookie from a request
// and decodes it to a ticket.
func decodeTicketFromRequest(req *http.Request, cookieOpts *options.Cookie) (*ticket, error) {
	requestCookie, err := req.Cookie(cookieOpts.Name)
	if err != nil {
		// Don't wrap this error to allow `err == http.ErrNoCookie` checks
		return nil, err
	}

	// An existing cookie exists, try to retrieve the ticket
	val, _, ok := encryption.Validate(requestCookie, cookieOpts.Secret, cookieOpts.Expire)
	if !ok {
		return nil, fmt.Errorf("session ticket cookie failed validation: %v", err)
	}

	// Valid cookie, decode the ticket
	return decodeTicket(string(val), cookieOpts)
}

// saveSession encodes the SessionState with the ticket's secret and persists
// it to disk via the passed saveFunc.
func (t *ticket) saveSession(s *sessions.SessionState, saver saveFunc) error {
	c, err := t.makeCipher()
	if err != nil {
		return err
	}
	ciphertext, err := s.EncodeSessionState(c, false)
	if err != nil {
		return fmt.Errorf("failed to encode the session state with the ticket: %v", err)
	}
	return saver(t.id, ciphertext, t.options.Expire)
}

// loadSession loads a session from the disk store via the passed loadFunc
// using the ticket.id as the key. It then decodes the SessionState using
// ticket.secret to make the AES-GCM cipher.
// finally it appends a lock implementation
func (t *ticket) loadSession(loader loadFunc, initLock initLockFunc) (*sessions.SessionState, error) {
	ciphertext, err := loader(t.id)
	if err != nil {
		return nil, fmt.Errorf("failed to load the session state with the ticket: %v", err)
	}
	c, err := t.makeCipher()
	if err != nil {
		return nil, err
	}

	sessionState, err := sessions.DecodeSessionState(ciphertext, c, false)
	if err != nil {
		return nil, err
	}
	lock := initLock(t.id)
	sessionState.Lock = lock
	return sessionState, nil
}

// clearSession uses the passed clearFunc to delete a session stored with a
// key of ticket.id
func (t *ticket) clearSession(clearer clearFunc) error {
	return clearer(t.id)
}

// setCookie sets the encoded ticket as a cookie
func (t *ticket) setCookie(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) error {
	ticketCookie, err := t.makeCookie(
		req,
		t.encodeTicket(),
		t.options.Expire,
		*s.CreatedAt,
	)
	if err != nil {
		return err
	}

	http.SetCookie(rw, ticketCookie)
	return nil
}

// clearCookie removes any cookies that would be where this ticket
// would set them
func (t *ticket) clearCookie(rw http.ResponseWriter, req *http.Request) {
	http.SetCookie(rw, cookies.MakeCookieFromOptions(
		req,
		t.options.Name,
		"",
		t.options,
		time.Hour*-1,
		time.Now(),
	))
}

// makeCookie makes a cookie, signing the value if present
func (t *ticket) makeCookie(req *http.Request, value string, expires time.Duration, now time.Time) (*http.Cookie, error) {
	if value != "" {
		var err error
		value, err = encryption.SignedValue(t.options.Secret, t.options.Name, []byte(value), now)
		if err != nil {
			return nil, err
		}
	}
	return cookies.MakeCookieFromOptions(
		req,
		t.options.Name,
		value,
		t.options,
		expires,
		now,
	), nil
}

// makeCipher makes a AES-GCM cipher out of the ticket's secret
func (t *ticket) makeCipher() (encryption.Cipher, error) {
	c, err := encryption.NewGCMCipher(t.secret)
	if err != nil {
		return nil, fmt.Errorf("failed to make an AES-GCM cipher from the ticket secret: %v", err)
	}
	return c, nil
}
