package redis

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/go-redis/redis"
	"github.com/pusher/oauth2_proxy/pkg/apis/options"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/cookies"
	"github.com/pusher/oauth2_proxy/pkg/encryption"
	"github.com/pusher/oauth2_proxy/pkg/logger"
)

// TicketData is a structure representing the ticket used in server session storage
type TicketData struct {
	TicketID string
	Secret   []byte
}

// SessionStore is an implementation of the sessions.SessionStore
// interface that stores sessions in redis
type SessionStore struct {
	CookieCipher  *encryption.Cipher
	CookieOptions *options.CookieOptions
	Client        *redis.Client
}

// NewRedisSessionStore initialises a new instance of the SessionStore from
// the configuration given
func NewRedisSessionStore(opts *options.SessionOptions, cookieOpts *options.CookieOptions) (sessions.SessionStore, error) {
	client, err := newRedisClient(opts.RedisStoreOptions)
	if err != nil {
		return nil, fmt.Errorf("error constructing redis client: %v", err)
	}

	rs := &SessionStore{
		Client:        client,
		CookieCipher:  opts.Cipher,
		CookieOptions: cookieOpts,
	}
	return rs, nil

}

func newRedisClient(opts options.RedisStoreOptions) (*redis.Client, error) {
	if opts.UseSentinel {
		client := redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    opts.SentinelMasterName,
			SentinelAddrs: opts.SentinelConnectionURLs,
		})
		return client, nil
	}

	opt, err := redis.ParseURL(opts.RedisConnectionURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse redis url: %s", err)
	}

	if opts.RedisInsecureTLS != false {
		opt.TLSConfig.InsecureSkipVerify = true
	}

	if opts.RedisCAPath != "" {
		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			logger.Printf("failed to load system cert pool for redis connection, falling back to empty cert pool")
		}
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		certs, err := ioutil.ReadFile(opts.RedisCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load %q, %v", opts.RedisCAPath, err)
		}

		// Append our cert to the system pool
		if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
			logger.Printf("no certs appended, using system certs only")
		}

		opt.TLSConfig.RootCAs = rootCAs
	}

	client := redis.NewClient(opt)
	return client, nil
}

// Save takes a sessions.SessionState and stores the information from it
// to redies, and adds a new ticket cookie on the HTTP response writer
func (store *SessionStore) Save(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) error {
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now()
	}

	// Old sessions that we are refreshing would have a request cookie
	// New sessions don't, so we ignore the error. storeValue will check requestCookie
	requestCookie, _ := req.Cookie(store.CookieOptions.CookieName)
	value, err := s.EncodeSessionState(store.CookieCipher)
	if err != nil {
		return err
	}
	ticketString, err := store.storeValue(value, store.CookieOptions.CookieExpire, requestCookie)
	if err != nil {
		return err
	}

	ticketCookie := store.makeCookie(
		req,
		ticketString,
		store.CookieOptions.CookieExpire,
		s.CreatedAt,
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

	val, _, ok := encryption.Validate(requestCookie, store.CookieOptions.CookieSecret, store.CookieOptions.CookieExpire)
	if !ok {
		return nil, fmt.Errorf("Cookie Signature not valid")
	}
	session, err := store.loadSessionFromString(val)
	if err != nil {
		return nil, fmt.Errorf("error loading session: %s", err)
	}
	return session, nil
}

// loadSessionFromString loads the session based on the ticket value
func (store *SessionStore) loadSessionFromString(value string) (*sessions.SessionState, error) {
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
	// We go ahead and clear the cookie first, always.
	clearCookie := store.makeCookie(
		req,
		"",
		time.Hour*-1,
		time.Now(),
	)
	http.SetCookie(rw, clearCookie)

	// If there was an existing cookie we should clear the session in redis
	requestCookie, err := req.Cookie(store.CookieOptions.CookieName)
	if err != nil && err == http.ErrNoCookie {
		// No existing cookie so can't clear redis
		return nil
	} else if err != nil {
		return fmt.Errorf("error retrieving cookie: %v", err)
	}

	val, _, ok := encryption.Validate(requestCookie, store.CookieOptions.CookieSecret, store.CookieOptions.CookieExpire)
	if !ok {
		return fmt.Errorf("Cookie Signature not valid")
	}

	// We only return an error if we had an issue with redis
	// If there's an issue decoding the ticket, ignore it
	ticket, _ := decodeTicket(store.CookieOptions.CookieName, val)
	if ticket != nil {
		_, err := store.Client.Del(ticket.asHandle(store.CookieOptions.CookieName)).Result()
		if err != nil {
			return fmt.Errorf("error clearing cookie from redis: %s", err)
		}
	}
	return nil
}

// makeCookie makes a cookie, signing the value if present
func (store *SessionStore) makeCookie(req *http.Request, value string, expires time.Duration, now time.Time) *http.Cookie {
	if value != "" {
		value = encryption.SignedValue(store.CookieOptions.CookieSecret, store.CookieOptions.CookieName, value, now)
	}
	return cookies.MakeCookieFromOptions(
		req,
		store.CookieOptions.CookieName,
		value,
		store.CookieOptions,
		expires,
		now,
	)
}

func (store *SessionStore) storeValue(value string, expiration time.Duration, requestCookie *http.Cookie) (string, error) {
	ticket, err := store.getTicket(requestCookie)
	if err != nil {
		return "", fmt.Errorf("error getting ticket: %v", err)
	}

	ciphertext := make([]byte, len(value))
	block, err := aes.NewCipher(ticket.Secret)
	if err != nil {
		return "", fmt.Errorf("error initiating cipher block %s", err)
	}

	// Use secret as the Initialization Vector too, because each entry has it's own key
	stream := cipher.NewCFBEncrypter(block, ticket.Secret)
	stream.XORKeyStream(ciphertext, []byte(value))

	handle := ticket.asHandle(store.CookieOptions.CookieName)
	err = store.Client.Set(handle, ciphertext, expiration).Err()
	if err != nil {
		return "", err
	}
	return ticket.encodeTicket(store.CookieOptions.CookieName), nil
}

// getTicket retrieves an existing ticket from the cookie if present,
// or creates a new ticket
func (store *SessionStore) getTicket(requestCookie *http.Cookie) (*TicketData, error) {
	if requestCookie == nil {
		return newTicket()
	}

	// An existing cookie exists, try to retrieve the ticket
	val, _, ok := encryption.Validate(requestCookie, store.CookieOptions.CookieSecret, store.CookieOptions.CookieExpire)
	if !ok {
		// Cookie is invalid, create a new ticket
		return newTicket()
	}

	// Valid cookie, decode the ticket
	ticket, err := decodeTicket(store.CookieOptions.CookieName, val)
	if err != nil {
		// If we can't decode the ticket we have to create a new one
		return newTicket()
	}
	return ticket, nil
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
