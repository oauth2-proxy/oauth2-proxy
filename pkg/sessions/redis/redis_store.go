package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
	"github.com/redis/go-redis/v9"
)

// SessionStore is an implementation of the persistence.Store
// interface that stores sessions in redis
type SessionStore struct {
	Client Client
}

// NewRedisSessionStore initialises a new instance of the SessionStore and wraps
// it in a persistence.Manager
func NewRedisSessionStore(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, error) {
	client, err := NewRedisClient(opts.Redis)
	if err != nil {
		return nil, fmt.Errorf("error constructing redis client: %v", err)
	}

	rs := &SessionStore{
		Client: client,
	}
	return persistence.NewManager(rs, cookieOpts, opts.Redis.EnforceSingleSession), nil
}

// Save takes a sessions.SessionState and stores the information from it
// to redis, and adds a new persistence cookie on the HTTP response writer
func (store *SessionStore) Save(ctx context.Context, key string, value []byte, exp time.Duration) error {
	err := store.Client.Set(ctx, key, value, exp)
	if err != nil {
		return fmt.Errorf("error saving redis session: %v", err)
	}
	return nil
}

const (

	// Prefix mapping keys with this string followed by a semicolon
	mappingNamespace = "email"

	// When attempting to obtain the lock, if it's not done before this timeout
	// then exit and fail the refresh attempt.
	// TODO: This should probably be configurable by the end user.
	mappingUpdateObtainTimeout = 5 * time.Second

	// Maximum time allowed for a session refresh attempt.
	// If the refresh request isn't finished within this time, the lock will be
	// released.
	// TODO: This should probably be configurable by the end user.
	mappingUpdateLockDuration = 2 * time.Second

	// How long to wait after failing to obtain the lock before trying again.
	// TODO: This should probably be configurable by the end user.
	mappingUpdateRetryPeriod = 10 * time.Millisecond
)

// SaveAndEvict takes a sessions.SessionState and stores the information from it
// to redis, invalidating any existing session for this user, maintains a bookkeeping map of email to session key, and
// adds a new persistence cookie on the HTTP response writer
func (store *SessionStore) SaveAndEvict(ctx context.Context, key string, value []byte, email string, exp time.Duration) error {
	err := store.Client.Set(ctx, key, value, exp)
	if err != nil {
		return fmt.Errorf("error saving redis session: %v", err)
	}
	emailKey := addNameSpace(email)
	lock := store.Client.Lock(fmt.Sprintf("%s.lock", emailKey))

	var lockObtained bool
	ctx, cancel := context.WithTimeout(ctx, mappingUpdateObtainTimeout)
	defer cancel()

	for !lockObtained {
		select {
		case <-ctx.Done():
			return errors.New("timeout obtaining mapping update lock")
		default:
			err := lock.Obtain(ctx, mappingUpdateLockDuration)
			if err != nil && !errors.Is(err, sessions.ErrLockNotObtained) {
				return fmt.Errorf("error occurred while trying to obtain lock: %v", err)
			} else if errors.Is(err, sessions.ErrLockNotObtained) {
				time.Sleep(mappingUpdateRetryPeriod)
				continue
			}
			// No error means we obtained the lock
			lockObtained = true
		}
	}

	defer func(lock sessions.Lock, ctx context.Context) {
		_ = lock.Release(ctx)
	}(lock, ctx)

	lastSession, err := store.Client.GetSet(ctx, emailKey, []byte(key))
	if err != nil && err != redis.Nil {
		return fmt.Errorf("error saving redis user to session mapping: %v", err)
	}
	if len(lastSession) > 0 {
		err = store.Client.Del(ctx, string(lastSession))
		if err != nil {
			// Deleting a missing key will result in a zero count so this an actual error
			return fmt.Errorf("error evicting previous redis session: %v", err)
		}
	}
	return nil
}

func addNameSpace(user string) string {
	return fmt.Sprintf("%s:%s", mappingNamespace, user)
}

// Load reads sessions.SessionState information from a persistence
// cookie within the HTTP request object
func (store *SessionStore) Load(ctx context.Context, key string) ([]byte, error) {
	value, err := store.Client.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("error loading redis session: %v", err)
	}
	return value, nil
}

// Clear clears any saved session information for a given persistence cookie
// from redis, and then clears the session
func (store *SessionStore) Clear(ctx context.Context, key string) error {
	err := store.Client.Del(ctx, key)
	if err != nil {
		return fmt.Errorf("error clearing the session from redis: %v", err)
	}
	return nil
}

// Lock creates a lock object for sessions.SessionState
func (store *SessionStore) Lock(key string) sessions.Lock {
	return store.Client.Lock(key)
}

// VerifyConnection verifies the redis connection is valid and the
// server is responsive
func (store *SessionStore) VerifyConnection(ctx context.Context) error {
	return store.Client.Ping(ctx)
}

// NewRedisClient makes a redis.Client (either standalone, sentinel aware, or
// redis cluster)
func NewRedisClient(opts options.RedisStoreOptions) (Client, error) {
	if opts.UseSentinel && opts.UseCluster {
		return nil, fmt.Errorf("options redis-use-sentinel and redis-use-cluster are mutually exclusive")
	}
	if opts.UseSentinel {
		return buildSentinelClient(opts)
	}
	if opts.UseCluster {
		return buildClusterClient(opts)
	}

	return buildStandaloneClient(opts)
}

// buildSentinelClient makes a redis.Client that connects to Redis Sentinel
// for Primary/Replica Redis node coordination
func buildSentinelClient(opts options.RedisStoreOptions) (Client, error) {
	addrs, opt, err := parseRedisURLs(opts.SentinelConnectionURLs)
	if err != nil {
		return nil, fmt.Errorf("could not parse redis urls: %v", err)
	}

	if opts.Password != "" {
		opt.Password = opts.Password
	}
	if opts.Username != "" {
		opt.Username = opts.Username
	}

	if err := setupTLSConfig(opts, opt); err != nil {
		return nil, err
	}

	client := redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:       opts.SentinelMasterName,
		SentinelAddrs:    addrs,
		SentinelPassword: opts.SentinelPassword,
		Username:         opts.Username,
		Password:         opts.Password,
		TLSConfig:        opt.TLSConfig,
		ConnMaxIdleTime:  time.Duration(opts.IdleTimeout) * time.Second,
	})
	return newClient(client), nil
}

// buildClusterClient makes a redis.Client that is Redis Cluster aware
func buildClusterClient(opts options.RedisStoreOptions) (Client, error) {
	addrs, opt, err := parseRedisURLs(opts.ClusterConnectionURLs)
	if err != nil {
		return nil, fmt.Errorf("could not parse redis urls: %v", err)
	}

	if opts.Password != "" {
		opt.Password = opts.Password
	}
	if opts.Username != "" {
		opt.Username = opts.Username
	}

	if err := setupTLSConfig(opts, opt); err != nil {
		return nil, err
	}

	client := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs:           addrs,
		Username:        opts.Username,
		Password:        opts.Password,
		TLSConfig:       opt.TLSConfig,
		ConnMaxIdleTime: time.Duration(opts.IdleTimeout) * time.Second,
	})
	return newClusterClient(client), nil
}

// buildStandaloneClient makes a redis.Client that connects to a simple
// Redis node
func buildStandaloneClient(opts options.RedisStoreOptions) (Client, error) {
	opt, err := redis.ParseURL(opts.ConnectionURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse redis url: %s", err)
	}

	if opts.Password != "" {
		opt.Password = opts.Password
	}
	if opts.Username != "" {
		opt.Username = opts.Username
	}

	if err := setupTLSConfig(opts, opt); err != nil {
		return nil, err
	}

	opt.ConnMaxIdleTime = time.Duration(opts.IdleTimeout) * time.Second

	client := redis.NewClient(opt)
	return newClient(client), nil
}

// setupTLSConfig sets the TLSConfig if the TLS option is given in redis.Options
func setupTLSConfig(opts options.RedisStoreOptions, opt *redis.Options) error {
	if opts.InsecureSkipTLSVerify {
		if opt.TLSConfig == nil {
			/* #nosec */
			opt.TLSConfig = &tls.Config{}
		}

		opt.TLSConfig.InsecureSkipVerify = true
	}

	if opts.CAPath != "" {
		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			logger.Errorf("failed to load system cert pool for redis connection, falling back to empty cert pool")
		}
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		certs, err := os.ReadFile(opts.CAPath)
		if err != nil {
			return fmt.Errorf("failed to load %q, %v", opts.CAPath, err)
		}

		// Append our cert to the system pool
		if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
			logger.Errorf("no certs appended, using system certs only")
		}

		if opt.TLSConfig == nil {
			/* #nosec */
			opt.TLSConfig = &tls.Config{}
		}

		opt.TLSConfig.RootCAs = rootCAs
	}
	return nil
}

// parseRedisURLs parses a list of redis urls and returns a list
// of addresses in the form of host:port and redis.Options that can be used to connect to Redis
func parseRedisURLs(urls []string) ([]string, *redis.Options, error) {
	addrs := []string{}
	var redisOptions *redis.Options
	for _, u := range urls {
		parsedURL, err := redis.ParseURL(u)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse redis url: %v", err)
		}
		addrs = append(addrs, parsedURL.Addr)
		redisOptions = parsedURL
	}
	return addrs, redisOptions, nil
}

var _ persistence.Store = (*SessionStore)(nil)
