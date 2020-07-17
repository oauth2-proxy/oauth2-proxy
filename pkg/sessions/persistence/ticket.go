package persistence

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/cookies"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
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

// Ticket is a structure representing the ticket used in server based
// session storage. It provides a unique per session decryption secret giving
// more security than the shared CookieSecret.
type Ticket struct {
	TicketID string
	Secret   []byte
	Options  *options.Cookie
}

// NewTicket creates a new ticket. TicketID & Secret will be randomly created
// with 16 byte sizes. The TicketID will be prefixed & hex encoded.
func NewTicket(cookieOpts *options.Cookie) (*Ticket, error) {
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

	ticket := &Ticket{
		TicketID: ticketID,
		Secret:   secret,
		Options:  cookieOpts,
	}
	return ticket, nil
}

// EncodeTicket encodes the Ticket to a string for usage in cookies.
func (t *Ticket) EncodeTicket() string {
	return fmt.Sprintf("%s.%s", t.TicketID, base64.RawURLEncoding.EncodeToString(t.Secret))
}

// DecodeTicket decodes a Ticket
func DecodeTicket(ticket string, cookieOpts *options.Cookie) (*Ticket, error) {
	ticketParts := strings.Split(ticket, ".")
	if len(ticketParts) != 2 {
		return nil, fmt.Errorf("failed to decode ticket")
	}
	ticketID, secretBase64 := ticketParts[0], ticketParts[1]

	secret, err := base64.RawURLEncoding.DecodeString(secretBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption secret: %v", err)
	}

	Ticket := &Ticket{
		TicketID: ticketID,
		Secret:   secret,
		Options:  cookieOpts,
	}
	return Ticket, nil
}

// DecodeTicketFromCookie retrieves a potential Ticket cookie from a request
// and decodes it to a Ticket.
func DecodeTicketFromRequest(req *http.Request, cookieOpts *options.Cookie) (*Ticket, error) {
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
	ticket, err := DecodeTicket(string(val), cookieOpts)
	if err != nil {
		return nil, err
	}
	return ticket, nil
}

// SaveSession encodes the SessionState with the Ticket's secret and persists
// it to disk via the passed SaveFunc.
func (t *Ticket) SaveSession(s *sessions.SessionState, saver SaveFunc) error {
	c, err := t.makeCipher()
	if err != nil {
		return err
	}
	ciphertext, err := s.EncodeSessionState(c, false)
	if err != nil {
		return fmt.Errorf("failed to encode the session state with the ticket: %v", err)
	}
	return saver(t.TicketID, ciphertext, t.Options.Expire)
}

// LoadSession loads a session from the disk store via the passed LoadFunc
// using the TicketID as the key. It then decodeds the SessionState using
// Ticket.Secret to make the AES-GCM cipher.
//
// TODO (@NickMeves): Remove legacyV5LoadSession support in V7
func (t *Ticket) LoadSession(loader LoadFunc) (*sessions.SessionState, error) {
	ciphertext, err := loader(t.TicketID)
	if err != nil {
		return nil, fmt.Errorf("failed to load the session state with the ticket: %v", err)
	}
	c, err := t.makeCipher()
	if err != nil {
		return nil, err
	}
	ss, err := sessions.DecodeSessionState(ciphertext, c, false)
	if err != nil {
		return t.legacyV5LoadSession(ciphertext)
	}
	return ss, nil
}

// ClearSession uses the passed ClearFunc to delete a session stored with a
// key of TicketID
func (t *Ticket) ClearSession(clearer ClearFunc) error {
	return clearer(t.TicketID)
}

// SetCookie sets the encoded Ticket as a cookie
func (t *Ticket) SetCookie(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) {
	ticketCookie := t.makeCookie(
		req,
		t.EncodeTicket(),
		t.Options.Expire,
		*s.CreatedAt,
	)

	http.SetCookie(rw, ticketCookie)
}

// ClearCookie removes any cookies that would be where this Ticket would set
// them
func (t *Ticket) ClearCookie(rw http.ResponseWriter, req *http.Request) {
	clearCookie := t.makeCookie(
		req,
		"",
		time.Hour*-1,
		time.Now(),
	)
	http.SetCookie(rw, clearCookie)
}

// makeCookie makes a cookie, signing the value if present
func (t *Ticket) makeCookie(req *http.Request, value string, expires time.Duration, now time.Time) *http.Cookie {
	if value != "" {
		value = encryption.SignedValue(t.Options.Secret, t.Options.Name, []byte(value), now)
	}
	return cookies.MakeCookieFromOptions(
		req,
		t.Options.Name,
		value,
		t.Options,
		expires,
		now,
	)
}

// makeCipher makes a AES-GCM cipher out of the Ticket.Secret
func (t *Ticket) makeCipher() (encryption.Cipher, error) {
	c, err := encryption.NewGCMCipher(t.Secret)
	if err != nil {
		return nil, fmt.Errorf("failed to make an AES-GCM cipher from the ticket secret: %v", err)
	}
	return c, nil
}

// legacyV5LoadSession loads a Redis session created in V5 with historical logic
//
// TODO (@NickMeves): Remove in V7
func (t *Ticket) legacyV5LoadSession(resultBytes []byte) (*sessions.SessionState, error) {
	block, err := aes.NewCipher(t.Secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create a legacy AES-CFB cipher from the ticket secret: %v", err)
	}

	stream := cipher.NewCFBDecrypter(block, t.Secret)
	stream.XORKeyStream(resultBytes, resultBytes)

	cfbCipher, err := encryption.NewCFBCipher(encryption.SecretBytes(t.Options.Secret))
	if err != nil {
		return nil, err
	}
	legacyCipher := encryption.NewBase64Cipher(cfbCipher)

	session, err := sessions.LegacyV5DecodeSessionState(string(resultBytes), legacyCipher)
	if err != nil {
		return nil, err
	}
	return session, nil
}
