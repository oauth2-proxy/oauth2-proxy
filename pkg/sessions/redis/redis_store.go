package redis

import (
	"context"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/go-redis/redis/v7"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/sessions/persistence"
)

// RedisStore is an implementation of the persistence.Store
// interface that stores sessions in redis
type RedisStore struct {
	Client Client
}

// NewRedisSessionStore initialises a new instance of the RedisStore and wraps
// it in a persistence.Manager
func NewRedisSessionStore(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, error) {
	client, err := newRedisClient(opts.Redis)
	if err != nil {
		return nil, fmt.Errorf("error constructing redis client: %v", err)
	}

	rs := &RedisStore{
		Client: client,
	}
	return persistence.NewManager(rs, cookieOpts), nil
}

// Save takes a sessions.SessionState and stores the information from it
// to redies, and adds a new persistence cookie on the HTTP response writer
func (store *RedisStore) Save(ctx context.Context, key string, value []byte, exp time.Duration) error {
	return store.Client.Set(ctx, key, value, exp)
}

// Load reads sessions.SessionState information from a persistence
// cookie within the HTTP request object
func (store *RedisStore) Load(ctx context.Context, key string) ([]byte, error) {
	return store.Client.Get(ctx, key)
}

// Clear clears any saved session information for a given persistence cookie
// from redis, and then clears the session
func (store *RedisStore) Clear(ctx context.Context, key string) error {
	return store.Client.Del(ctx, key)
}

// newRedisClient makes a redis.Client (either standalone, sentinel aware, or
// redis cluster)
func newRedisClient(opts options.RedisStoreOptions) (Client, error) {
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

// buildClusterClient makes a redis.Client that is Redis Cluster aware
func buildClusterClient(opts options.RedisStoreOptions) (Client, error) {
	addrs, err := parseRedisURLs(opts.ClusterConnectionURLs)
	if err != nil {
		return nil, fmt.Errorf("could not parse redis urls: %v", err)
	}
	client := redis.NewClusterClient(&redis.ClusterOptions{
		Addrs: addrs,
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
