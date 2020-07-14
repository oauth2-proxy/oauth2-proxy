package redis

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/go-redis/redis/v7"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/sessions/persistence"
)

// SessionStore is an implementation of the sessions.SessionStore
// interface that stores sessions in redis
type SessionStore struct {
	CookieCipher encryption.Cipher
	Cookie       *options.Cookie
	Client       Client
}

// NewRedisSessionStore initialises a new instance of the SessionStore from
// the configuration given
func NewRedisSessionStore(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, error) {
	cfbCipher, err := encryption.NewCFBCipher(encryption.SecretBytes(cookieOpts.Secret))
	if err != nil {
		return nil, fmt.Errorf("error initialising cipher: %v", err)
	}

	client, err := newRedisCmdable(opts.Redis)
	if err != nil {
		return nil, fmt.Errorf("error constructing redis client: %v", err)
	}

	rs := &SessionStore{
		Client:       client,
		CookieCipher: cfbCipher,
		Cookie:       cookieOpts,
	}
	return rs, nil
}

// Save takes a sessions.SessionState and stores the information from it
// to redies, and adds a new persistence cookie on the HTTP response writer
func (store *SessionStore) Save(rw http.ResponseWriter, req *http.Request, s *sessions.SessionState) error {
	m := persistence.NewManager(rw, req, store.Cookie)
	return m.Save(s, func(key string, value []byte, exp time.Duration) error {
		return store.Client.Set(req.Context(), key, value, exp)
	})
}

// Load reads sessions.SessionState information from a persistence
// cookie within the HTTP request object
func (store *SessionStore) Load(req *http.Request) (*sessions.SessionState, error) {
	m := persistence.NewManager(nil, req, store.Cookie)
	return m.Load(func(key string) ([]byte, error) {
		return store.Client.Get(req.Context(), key)
	})
}

// Clear clears any saved session information for a given persistence cookie
// from redis, and then clears the session
func (store *SessionStore) Clear(rw http.ResponseWriter, req *http.Request) error {
	m := persistence.NewManager(rw, req, store.Cookie)
	return m.Clear(func(key string) error {
		return store.Client.Del(req.Context(), key)
	})
}

func newRedisCmdable(opts options.RedisStoreOptions) (Client, error) {
	if opts.UseSentinel && opts.UseCluster {
		return nil, fmt.Errorf("options redis-use-sentinel and redis-use-cluster are mutually exclusive")
	}

	if opts.UseSentinel {
		addrs, err := parseRedisURLs(opts.SentinelConnectionURLs)
		if err != nil {
			return nil, fmt.Errorf("could not parse redis urls: %v", err)
		}
		client := redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    opts.SentinelMasterName,
			SentinelAddrs: addrs,
		})
		return newClient(client), nil
	}

	if opts.UseCluster {
		addrs, err := parseRedisURLs(opts.ClusterConnectionURLs)
		if err != nil {
			return nil, fmt.Errorf("could not parse redis urls: %v", err)
		}
		client := redis.NewClusterClient(&redis.ClusterOptions{
			Addrs: addrs,
		})
		return newClusterClient(client), nil
	}

	opt, err := redis.ParseURL(opts.ConnectionURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse redis url: %s", err)
	}

	if opts.InsecureSkipTLSVerify {
		opt.TLSConfig.InsecureSkipVerify = true
	}

	if opts.CAPath != "" {
		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			logger.Printf("failed to load system cert pool for redis connection, falling back to empty cert pool")
		}
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		certs, err := ioutil.ReadFile(opts.CAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load %q, %v", opts.CAPath, err)
		}

		// Append our cert to the system pool
		if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
			logger.Printf("no certs appended, using system certs only")
		}

		opt.TLSConfig.RootCAs = rootCAs
	}

	client := redis.NewClient(opt)
	return newClient(client), nil
}

// parseRedisURLs parses a list of redis urls and returns a list
// of addresses in the form of host:port that can be used to connnect to Redis
func parseRedisURLs(urls []string) ([]string, error) {
	addrs := []string{}
	for _, u := range urls {
		parsedURL, err := redis.ParseURL(u)
		if err != nil {
			return nil, fmt.Errorf("unable to parse redis url: %v", err)
		}
		addrs = append(addrs, parsedURL.Addr)
	}
	return addrs, nil
}
