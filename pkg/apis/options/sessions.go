package options

import (
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
)

type SessionStoreType string

const (
	// CookieSessionStoreType is used to indicate the CookieSessionStore should be
	// used for storing sessions.
	CookieSessionStoreType SessionStoreType = "cookie"

	// RedisSessionStoreType is used to indicate the RedisSessionStore should be
	// used for storing sessions.
	RedisSessionStoreType SessionStoreType = "redis"

	// DefaultCookieStoreMinimal is the default value for CookieStoreOptions.Minimal
	DefaultCookieStoreMinimal bool = false

	// DefaultRedisStoreUseSentinel is the default value for RedisStoreOptions.UseSentinel
	DefaultRedisStoreUseSentinel bool = false

	// DefaultRedisStoreUseCluster is the default value for RedisStoreOptions.UseCluster
	DefaultRedisStoreUseCluster bool = false

	// DefaultRedisStoreInsecureSkipTLSVerify is the default value for RedisStoreOptions.InsecureSkipTLSVerify
	DefaultRedisStoreInsecureSkipTLSVerify bool = false
)

// SessionOptions contains configuration options for the SessionStore providers.
type SessionOptions struct {
	// Type is the type of session store to use
	// Options are "cookie" or "redis"
	// Default is "cookie"
	Type SessionStoreType `yaml:"type,omitempty"`
	// Refresh is the duration after which the session is refreshable
	Refresh time.Duration `yaml:"refresh,omitempty"`
	// Cookie is the configuration options for the CookieSessionStore
	Cookie CookieStoreOptions `yaml:"cookie,omitempty"`
	// Redis is the configuration options for the RedisSessionStore
	Redis RedisStoreOptions `yaml:"redis,omitempty"`
}

// CookieStoreOptions contains configuration options for the CookieSessionStore.
type CookieStoreOptions struct {
	// Minimal indicates whether to use minimal cookies for session storage
	// Default is false
	Minimal *bool `yaml:"minimal,omitempty"`
}

// RedisStoreOptions contains configuration options for the RedisSessionStore.
type RedisStoreOptions struct {
	// ConnectionURL is the Redis connection URL
	ConnectionURL string `yaml:"connectionURL,omitempty"`
	// Username is the Redis username
	Username string `yaml:"username,omitempty"`
	// Password is the Redis password
	Password string `yaml:"password,omitempty"`
	// UseSentinel indicates whether to use Redis Sentinel
	// Default is false
	UseSentinel *bool `yaml:"useSentinel,omitempty"`
	// SentinelPassword is the Redis Sentinel password
	SentinelPassword string `yaml:"sentinelPassword,omitempty"`
	// SentinelMasterName is the Redis Sentinel master name
	SentinelMasterName string `yaml:"sentinelMasterName,omitempty"`
	// SentinelConnectionURLs is a list of Redis Sentinel connection URLs
	SentinelConnectionURLs []string `yaml:"sentinelConnectionURLs,omitempty"`
	// UseCluster indicates whether to use Redis Cluster
	// Default is false
	UseCluster *bool `yaml:"useCluster,omitempty"`
	// ClusterConnectionURLs is a list of Redis Cluster connection URLs
	ClusterConnectionURLs []string `yaml:"clusterConnectionURLs,omitempty"`
	// CAPath is the path to the CA certificate for Redis TLS connections
	CAPath string `yaml:"caPath,omitempty"`
	// InsecureSkipTLSVerify indicates whether to skip TLS verification for Redis connections
	InsecureSkipTLSVerify *bool `yaml:"insecureSkipTLSVerify,omitempty"`
	// IdleTimeout is the Redis connection idle timeout in seconds
	IdleTimeout int `yaml:"idleTimeout,omitempty"`
}

// EnsureDefaults sets default values for SessionOptions
func (s *SessionOptions) EnsureDefaults() {
	if s.Type == "" {
		s.Type = CookieSessionStoreType
	}
	if s.Cookie.Minimal == nil {
		s.Cookie.Minimal = ptr.To(DefaultCookieStoreMinimal)
	}
	if s.Redis.UseSentinel == nil {
		s.Redis.UseSentinel = ptr.To(DefaultRedisStoreUseSentinel)
	}
	if s.Redis.UseCluster == nil {
		s.Redis.UseCluster = ptr.To(DefaultRedisStoreUseCluster)
	}
	if s.Redis.InsecureSkipTLSVerify == nil {
		s.Redis.InsecureSkipTLSVerify = ptr.To(DefaultRedisStoreInsecureSkipTLSVerify)
	}
}
