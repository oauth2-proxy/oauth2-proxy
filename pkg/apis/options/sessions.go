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

	// ConnectionURL is the host URL.
	ConnectionURL string `flag:"redis-connection-url" cfg:"redis_connection_url"`

	// Password required to allow connection with redis store.
	Password string `flag:"redis-password" cfg:"redis_password"`

	// UseSentinels will allow to use sentinels in case its value is set to true.
	UseSentinel bool `flag:"redis-use-sentinel" cfg:"redis_use_sentinel"`

	// SentinelPassword contains password for authorizing use of sentinel.
	SentinelPassword string `flag:"redis-sentinel-password" cfg:"redis_sentinel_password"`

	// SentinelMasterName is the name given to master.
	SentinelMasterName string `flag:"redis-sentinel-master-name" cfg:"redis_sentinel_master_name"`

	// SnetinelConnectionURLs contains the list of URLs used for connecting with the redis instances
	// to be included in the sentinel.
	SentinelConnectionURLs []string `flag:"redis-sentinel-connection-urls" cfg:"redis_sentinel_connection_urls"`

	// UseCluster sets the flag for using redis cluster or not.
	UseCluster bool `flag:"redis-use-cluster" cfg:"redis_use_cluster"`

	// ClusterConnectionURLs contains the list of URLs of redis instances to be included in the
	// cluster.
	ClusterConnectionURLs []string `flag:"redis-cluster-connection-urls" cfg:"redis_cluster_connection_urls"`

	// CAPath defines the path to certificates.
	CAPath string `flag:"redis-ca-path" cfg:"redis_ca_path"`

	// InsecureSkipTLSVerify will skip TLS verification of redis hosts.
	// Defaults to false.
	InsecureSkipTLSVerify bool `flag:"redis-insecure-skip-tls-verify" cfg:"redis_insecure_skip_tls_verify"`

	// IdleTimeout defines the time duration after which an idle redis connection
	// will timeout and be closed.
	IdleTimeout int `flag:"redis-connection-idle-timeout" cfg:"redis_connection_idle_timeout"`
}

func sessionOptionsDefaults() SessionOptions {
	return SessionOptions{
		Type: CookieSessionStoreType,
		Cookie: CookieStoreOptions{
			Minimal: false,
		},
	}
}
