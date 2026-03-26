package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
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
	return persistence.NewManager(rs, cookieOpts), nil
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

// Load reads sessions.SessionState information from a persistence
// cookie within the HTTP request object
func (store *SessionStore) Load(ctx context.Context, key string) ([]byte, error) {
	value, err := store.Client.Get(ctx, key)
	if err == redis.Nil {
		return nil, fmt.Errorf("session does not exist")
	} else if err != nil {
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
	if opts.IdleTimeout > 0 {
		opt.ConnMaxIdleTime = time.Duration(opts.IdleTimeout) * time.Second
	}

	if err := setupTLSConfig(opts, opt); err != nil {
		return nil, err
	}

	failoverOpts := &redis.FailoverOptions{
		MasterName:       opts.SentinelMasterName,
		SentinelAddrs:    addrs,
		SentinelPassword: opts.SentinelPassword,
		Username:         opt.Username,
		Password:         opt.Password,
		TLSConfig:        opt.TLSConfig,
		ConnMaxIdleTime:  opt.ConnMaxIdleTime,
	}

	if opts.UseIAMAuth {
		credsFn, err := newIAMCredentialsProvider(opts)
		if err != nil {
			return nil, err
		}
		failoverOpts.Username = ""
		failoverOpts.Password = ""
		failoverOpts.CredentialsProviderContext = credsFn
	}

	client := redis.NewFailoverClient(failoverOpts)
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
	if opts.IdleTimeout > 0 {
		opt.ConnMaxIdleTime = time.Duration(opts.IdleTimeout) * time.Second
	}

	if err := setupTLSConfig(opts, opt); err != nil {
		return nil, err
	}

	clusterOpts := &redis.ClusterOptions{
		Addrs:           addrs,
		Username:        opt.Username,
		Password:        opt.Password,
		TLSConfig:       opt.TLSConfig,
		ConnMaxIdleTime: opt.ConnMaxIdleTime,
	}

	if opts.UseIAMAuth {
		credsFn, err := newIAMCredentialsProvider(opts)
		if err != nil {
			return nil, err
		}
		clusterOpts.Username = ""
		clusterOpts.Password = ""
		clusterOpts.CredentialsProviderContext = credsFn
	}

	client := redis.NewClusterClient(clusterOpts)
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
	if opts.IdleTimeout > 0 {
		opt.ConnMaxIdleTime = time.Duration(opts.IdleTimeout) * time.Second
	}

	if err := setupTLSConfig(opts, opt); err != nil {
		return nil, err
	}

	if opts.UseIAMAuth {
		credsFn, err := newIAMCredentialsProvider(opts)
		if err != nil {
			return nil, err
		}
		opt.Username = ""
		opt.Password = ""
		opt.CredentialsProviderContext = credsFn
	}

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
	if len(urls) == 0 {
		return nil, nil, fmt.Errorf("unable to parse redis urls: no redis urls provided")
	}

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

// newIAMCredentialsProvider creates a go-redis CredentialsProviderContext
// that generates fresh IAM auth tokens on each new Redis connection.
func newIAMCredentialsProvider(opts options.RedisStoreOptions) (func(ctx context.Context) (string, string, error), error) {
	var cfgOpts []func(*awsconfig.LoadOptions) error
	if opts.IAMRegion != "" {
		cfgOpts = append(cfgOpts, awsconfig.WithRegion(opts.IAMRegion))
	}

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), cfgOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config for IAM Redis auth: %w", err)
	}

	gen := &iamTokenGenerator{
		userID:             opts.IAMUserID,
		replicationGroupID: opts.IAMReplicationGroupID,
		region:             cfg.Region,
		serverless:         opts.IAMServerless,
		credentials:        cfg.Credentials,
	}

	return func(ctx context.Context) (string, string, error) {
		token, err := gen.Generate(ctx)
		if err != nil {
			return "", "", err
		}
		return opts.IAMUserID, token, nil
	}, nil
}

var _ persistence.Store = (*SessionStore)(nil)
