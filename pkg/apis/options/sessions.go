package options

// SessionOptions contains configuration options for the SessionStore providers.
type SessionOptions struct {
	Type   string             `yaml:"type,omitempty"`
	Cookie CookieStoreOptions `yaml:"cookie,omitempty"`
	Redis  RedisStoreOptions  `yaml:"redis,omitempty"`
}

// CookieSessionStoreType is used to indicate the CookieSessionStore should be
// used for storing sessions.
var CookieSessionStoreType = "cookie"

// RedisSessionStoreType is used to indicate the RedisSessionStore should be
// used for storing sessions.
var RedisSessionStoreType = "redis"

// CookieStoreOptions contains configuration options for the CookieSessionStore.
type CookieStoreOptions struct {
	Minimal bool `yaml:"minimal,omitempty"`
}

// RedisStoreOptions contains configuration options for the RedisSessionStore.
type RedisStoreOptions struct {
	ConnectionURL          string   `yaml:"connectionURL,omitempty"`
	Password               string   `yaml:"password,omitempty"`
	Username               string   `yaml:"username,omitempty"`
	UseSentinel            bool     `yaml:"useSentinel,omitempty"`
	SentinelPassword       string   `yaml:"sentinelPassword,omitempty"`
	SentinelMasterName     string   `yaml:"sentinelMasterName,omitempty"`
	SentinelConnectionURLs []string `yaml:"sentinelConnectionURLs,omitempty"`
	UseCluster             bool     `yaml:"useCluster,omitempty"`
	ClusterConnectionURLs  []string `yaml:"clusterConnectionURLs,omitempty"`
	CAPath                 string   `yaml:"caPath,omitempty"`
	InsecureSkipTLSVerify  bool     `yaml:"insecureSkipTLSVerify,omitempty"`
	IdleTimeout            int      `yaml:"idleTimeout,omitempty"`
}

func sessionOptionsDefaults() SessionOptions {
	return SessionOptions{
		Type: CookieSessionStoreType,
		Cookie: CookieStoreOptions{
			Minimal: false,
		},
	}
}
