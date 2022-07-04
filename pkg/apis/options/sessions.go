package options

// SessionOptions contains configuration options for the SessionStore providers.
type SessionOptions struct {
	Type   string             `flag:"session-store-type" cfg:"session_store_type"`
	Cookie CookieStoreOptions `cfg:",squash"`
	Redis  RedisStoreOptions  `cfg:",squash"`
}

// CookieSessionStoreType is used to indicate the CookieSessionStore should be
// used for storing sessions.
var CookieSessionStoreType = "cookie"

// RedisSessionStoreType is used to indicate the RedisSessionStore should be
// used for storing sessions.
var RedisSessionStoreType = "redis"

// CookieStoreOptions contains configuration options for the CookieSessionStore.
type CookieStoreOptions struct {
	Minimal bool `flag:"session-cookie-minimal" cfg:"session_cookie_minimal"`
}

// RedisStoreOptions contains configuration options for the RedisSessionStore.
type RedisStoreOptions struct {
	ConnectionURL          string   `json:"-" flag:"redis-connection-url" cfg:"redis_connection_url"`
	Password               string   `json:"-" flag:"redis-password" cfg:"redis_password"`
	UseSentinel            bool     `json:"-" flag:"redis-use-sentinel" cfg:"redis_use_sentinel"`
	SentinelPassword       string   `json:"-" flag:"redis-sentinel-password" cfg:"redis_sentinel_password"`
	SentinelMasterName     string   `json:"-" flag:"redis-sentinel-master-name" cfg:"redis_sentinel_master_name"`
	SentinelConnectionURLs []string `json:"-" flag:"redis-sentinel-connection-urls" cfg:"redis_sentinel_connection_urls"`
	UseCluster             bool     `json:"-" flag:"redis-use-cluster" cfg:"redis_use_cluster"`
	ClusterConnectionURLs  []string `json:"-" flag:"redis-cluster-connection-urls" cfg:"redis_cluster_connection_urls"`
	CAPath                 string   `json:"-" flag:"redis-ca-path" cfg:"redis_ca_path"`
	InsecureSkipTLSVerify  bool     `json:"-" flag:"redis-insecure-skip-tls-verify" cfg:"redis_insecure_skip_tls_verify"`
	// KeyPrefix is a string to prepend to each Redis key created or queried by
	// oauth2-proxy. This is useful for restricting access to keys used by
	// oauth2-proxy via Redis ACLs.
	KeyPrefix string `json:"keyPrefix,omitempty" flag:"redis-key-prefix" cfg:"redis_key_prefix"`
}

func sessionOptionsDefaults() SessionOptions {
	return SessionOptions{
		Type: CookieSessionStoreType,
		Cookie: CookieStoreOptions{
			Minimal: false,
		},
	}
}
