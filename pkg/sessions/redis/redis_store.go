package redis

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

	"github.com/go-redis/redis"
	"github.com/pusher/oauth2_proxy/cookie"
	"github.com/pusher/oauth2_proxy/pkg/apis/options"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/cookies"
)

// TicketData is a structure representing the ticket used in server session storage
type TicketData struct {
	TicketID string
	Secret   []byte
}

// SessionStore is an implementation of the sessions.SessionStore
// interface that stores sessions in redis
type SessionStore struct {
	CookieCipher  *cookie.Cipher
	CookieOptions *options.CookieOptions
	Client        *redis.Client
}

// NewRedisSessionStore initialises a new instance of the SessionStore from
// the configuration given
func NewRedisSessionStore(opts *options.SessionOptions, cookieOpts *options.CookieOptions) (sessions.SessionStore, error) {
	opt, err := redis.ParseURL(opts.RedisStoreOptions.RedisConnectionURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse redis url: %s", err)
	}

	client := redis.NewClient(opt)

	rs := &SessionStore{
		Client:        client,
		CookieCipher:  opts.Cipher,
		CookieOptions: cookieOpts,
	}
	return rs, nil

}

// Save takes a sessions.SessionState and stores the information from it
// to redies, and adds a new ticket cookie on the HTTP response writer
func (store *SessionStore) Save(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) error {
	// Old sessions that we are refreshing would have a request cookie
	// New sessions don't, so we ignore the error. storeValue will check requestCookie
	requestCookie, _ := req.Cookie(store.CookieOptions.CookieName)
	value, err := s.EncodeSessionState(store.CookieCipher)
	if err != nil {
		return err
	}
	ticketString, err := store.storeValue(value, s.ExpiresOn, requestCookie)
	if err != nil {
		return err
	}

	ticketCookie := cookies.MakeCookieFromOptions(
		req,
		store.CookieOptions.CookieName,
		ticketString,
		store.CookieOptions,
		store.CookieOptions.CookieExpire,
		time.Now(),
	)

	http.SetCookie(rw, ticketCookie)
	return nil
}

// Load reads sessions.SessionState information from a ticket
// cookie within the HTTP request object
func (store *SessionStore) Load(req *http.Request) (*sessions.SessionState, error) {
	requestCookie, err := req.Cookie(store.CookieOptions.CookieName)
	if err != nil {
		return nil, fmt.Errorf("error loading session: %s", err)
	}
	// No cookie validation necessary
	session, err := store.LoadSessionFromString(requestCookie.Value)
	if err != nil {
		return nil, fmt.Errorf("error loading session: %s", err)
	}
	return session, nil
}

// LoadSessionFromString loads the session based on the ticket value
func (store *SessionStore) LoadSessionFromString(value string) (*sessions.SessionState, error) {
	ticket, err := decodeTicket(store.CookieOptions.CookieName, value)
	if err != nil {
		return nil, err
	}

	result, err := store.Client.Get(ticket.asHandle(store.CookieOptions.CookieName)).Result()
	if err != nil {
		return nil, err
	}

	resultBytes := []byte(result)
	block, err := aes.NewCipher(ticket.Secret)
	if err != nil {
		return nil, err
	}
	// Use secret as the IV too, because each entry has it's own key
	stream := cipher.NewCFBDecrypter(block, ticket.Secret)
	stream.XORKeyStream(resultBytes, resultBytes)

	session, err := sessions.DecodeSessionState(string(resultBytes), store.CookieCipher)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// Clear clears any saved session information for a given ticket cookie
// from redis, and then clears the session
func (store *SessionStore) Clear(rw http.ResponseWriter, req *http.Request) error {
	requestCookie, _ := req.Cookie(store.CookieOptions.CookieName)

	// We go ahead and clear the cookie first, always.
	clearCookie := cookies.MakeCookieFromOptions(
		req,
		store.CookieOptions.CookieName,
		"",
		store.CookieOptions,
		time.Hour*-1,
		time.Now(),
	)
	http.SetCookie(rw, clearCookie)

	// We only return an error if we had an issue with redis
	// If there's an issue decoding the ticket, ignore it
	ticket, _ := decodeTicket(store.CookieOptions.CookieName, requestCookie.Value)
	if ticket != nil {
		deleted, err := store.Client.Del(ticket.asHandle(store.CookieOptions.CookieName)).Result()
		fmt.Println("delted %n", deleted)
		if err != nil {
			return fmt.Errorf("error clearing cookie from redis: %s", err)
		}
	}
	return nil
}

func (store *SessionStore) storeValue(value string, expiresOn time.Time, requestCookie *http.Cookie) (string, error) {
	var ticket *TicketData
	if requestCookie != nil {
		var err error
		ticket, err = decodeTicket(store.CookieOptions.CookieName, requestCookie.Value)
		if err != nil {
			return "", err
		}
	} else {
		var err error
		ticket, err = newTicket()
		if err != nil {
			return "", fmt.Errorf("error creating new ticket: %s", err)
		}
	}

	ciphertext := make([]byte, len(value))
	block, err := aes.NewCipher(ticket.Secret)
	if err != nil {
		return "", fmt.Errorf("error initiating cipher block %s", err)
	}

	// Use secret as the IV too, because each entry has it's own key
	stream := cipher.NewCFBEncrypter(block, ticket.Secret)
	stream.XORKeyStream(ciphertext, []byte(value))

	handle := ticket.asHandle(store.CookieOptions.CookieName)
	expires := expiresOn.Sub(time.Now())
	err = store.Client.Set(handle, ciphertext, expires).Err()
	if err != nil {
		return "", err
	}
	return ticket.encodeTicket(store.CookieOptions.CookieName), nil
}

func newTicket() (*TicketData, error) {
	rawID := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, rawID); err != nil {
		return nil, fmt.Errorf("failed to create new ticket ID %s", err)
	}
	// ticketID is hex encoded
	ticketID := fmt.Sprintf("%x", rawID)

	secret := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return nil, fmt.Errorf("failed to create initialization vector %s", err)
	}
	ticket := &TicketData{
		TicketID: ticketID,
		Secret:   secret,
	}
	return ticket, nil
}

func (ticket *TicketData) asHandle(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, ticket.TicketID)
}

func decodeTicket(cookieName string, ticketString string) (*TicketData, error) {
	prefix := cookieName + "-"
	if !strings.HasPrefix(ticketString, prefix) {
		return nil, fmt.Errorf("failed to decode ticket handle")
	}
	trimmedTicket := strings.TrimPrefix(ticketString, prefix)

	ticketParts := strings.Split(trimmedTicket, ".")
	if len(ticketParts) != 2 {
		return nil, fmt.Errorf("failed to decode ticket")
	}
	ticketID, secretBase64 := ticketParts[0], ticketParts[1]

	// ticketID must be a hexadecimal string
	_, err := hex.DecodeString(ticketID)
	if err != nil {
		return nil, fmt.Errorf("server ticket failed sanity checks")
		// s is not a valid
	}

	secret, err := base64.RawURLEncoding.DecodeString(secretBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode initialization vector %s", err)
	}
	ticketData := &TicketData{
		TicketID: ticketID,
		Secret:   secret,
	}
	return ticketData, nil
}

func (ticket *TicketData) encodeTicket(prefix string) string {
	handle := ticket.asHandle(prefix)
	ticketString := handle + "." + base64.RawURLEncoding.EncodeToString(ticket.Secret)
	return ticketString
}
