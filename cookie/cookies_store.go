package cookie

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-redis/redis"
)

// ServerCookiesStore is the interface to storing cookies.
// It takes in cookies
type ServerCookiesStore interface {
	Store(responseCookie *http.Cookie, requestCookie *http.Cookie) (string, error)
	Clear(requestCookie *http.Cookie) (bool, error)
	Load(requestCookie *http.Cookie) (string, error)
}

// RedisCookieStore is an Redis-backed implementation of a ServerCookiesStore.
// It stores the cookies according to the cookie ticket, which is composed of
// a Prefix (the same as the CookieName) and a handle (a random identifier)
type RedisCookieStore struct {
	Client *redis.Client
	Block  cipher.Block
	Prefix string
}

// NewRedisCookieStore constructs a new Redis-backed Server cookie store.
func NewRedisCookieStore(url string, cookieName string, block cipher.Block) (*RedisCookieStore, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		panic(err)
	}

	client := redis.NewClient(opt)

	rs := &RedisCookieStore{
		Client: client,
		Prefix: cookieName,
		Block:  block,
	}
	// Create client as usually.
	return rs, nil
}

// Store stores the cookie locally and returns a new response cookie value to be
// sent back to the client. That value is used to lookup the cookie later.
func (store *RedisCookieStore) Store(responseCookie *http.Cookie, requestCookie *http.Cookie) (string, error) {
	var cookieHandle string
	var iv []byte
	if requestCookie != nil {
		var err error
		cookieHandle, iv, err = parseCookieTicket(store.Prefix, requestCookie.Value)
		if err != nil {
			return "", err
		}
	} else {
		hasher := sha1.New()
		hasher.Write([]byte(responseCookie.Value))
		cookieID := fmt.Sprintf("%x", hasher.Sum(nil))
		iv = make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return "", fmt.Errorf("failed to create initialization vector %s", err)
		}
		cookieHandle = fmt.Sprintf("%s-%s", store.Prefix, cookieID)
	}

	ciphertext := make([]byte, len(responseCookie.Value))
	stream := cipher.NewCFBEncrypter(store.Block, iv)
	stream.XORKeyStream(ciphertext, []byte(responseCookie.Value))

	expires := responseCookie.Expires.Sub(time.Now())
	err := store.Client.Set(cookieHandle, ciphertext, expires).Err()
	if err != nil {
		return "", err
	}

	cookieTicket := cookieHandle + "." + base64.RawURLEncoding.EncodeToString(iv)
	return cookieTicket, nil
}

// Clear takes in the client cookie from the request and uses it to
// clear any lingering server cookies, when possible. It returns true if anything
// was deleted.
func (store *RedisCookieStore) Clear(requestCookie *http.Cookie) (bool, error) {
	var err error
	cookieHandle, _, err := parseCookieTicket(store.Prefix, requestCookie.Value)
	if err != nil {
		return false, err
	}

	deleted, err := store.Client.Del(cookieHandle).Result()
	if err != nil {
		return false, err
	}
	return deleted > 0, nil
}

// Load takes in the client cookie from the request and uses it to lookup
// the stored value.
func (store *RedisCookieStore) Load(requestCookie *http.Cookie) (string, error) {
	cookieHandle, iv, err := parseCookieTicket(store.Prefix, requestCookie.Value)
	if err != nil {
		return "", err
	}

	result, err := store.Client.Get(cookieHandle).Result()
	if err != nil {
		return "", err
	}

	resultBytes := []byte(result)

	stream := cipher.NewCFBDecrypter(store.Block, iv)
	stream.XORKeyStream(resultBytes, resultBytes)
	return string(resultBytes), nil
}

func parseCookieTicket(cookieName string, ticket string) (string, []byte, error) {
	prefix := cookieName + "-"
	if !strings.HasPrefix(ticket, prefix) {
		return "", nil, fmt.Errorf("failed to decode cookie handle")
	}
	trimmedTicket := strings.TrimPrefix(ticket, prefix)

	cookieParts := strings.Split(trimmedTicket, ".")
	if len(cookieParts) != 2 {
		return "", nil, fmt.Errorf("failed to decode cookie")
	}
	cookieID, ivBase64 := cookieParts[0], cookieParts[1]
	cookieHandle := prefix + cookieID

	// cookieID must be a hexadecimal string
	_, err := hex.DecodeString(cookieID)
	if err != nil {
		return "", nil, fmt.Errorf("server cookie failed sanity checks")
		// s is not a valid
	}

	iv, err := base64.RawURLEncoding.DecodeString(ivBase64)
	if err != nil {
		return "", nil, fmt.Errorf("failed to decode initialization vector %s", err)
	}
	return cookieHandle, iv, nil
}
