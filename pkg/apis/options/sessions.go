package options

// SessionOptions contains configuration options for the SessionStore providers.
type SessionOptions struct {
	Type   string             `json:"type,omitempty"`
	Cookie CookieStoreOptions `json:"cookie,omitempty"`
	Redis  RedisStoreOptions  `json:"redis,omitempty"`
}

// CookieSessionStoreType is used to indicate the CookieSessionStore should be
// used for storing sessions.
var CookieSessionStoreType = "cookie"

// RedisSessionStoreType is used to indicate the RedisSessionStore should be
// used for storing sessions.
var RedisSessionStoreType = "redis"

// CookieStoreOptions contains configuration options for the CookieSessionStore.
type CookieStoreOptions struct {
	Minimal bool `json:"minimal,omitempty"`
}

// RedisStoreOptions contains configuration options for the RedisSessionStore.
type RedisStoreOptions struct {
	ConnectionURL          string   `json:"connectionURL,omitempty"`
	Password               string   `json:"password,omitempty"`
	Username               string   `json:"username,omitempty"`
	UseSentinel            bool     `json:"useSentinel,omitempty"`
	SentinelPassword       string   `json:"sentinelPassword,omitempty"`
	SentinelMasterName     string   `json:"sentinelMasterName,omitempty"`
	SentinelConnectionURLs []string `json:"sentinelConnectionURLs,omitempty"`
	UseCluster             bool     `json:"useCluster,omitempty"`
	ClusterConnectionURLs  []string `json:"clusterConnectionURLs,omitempty"`
	CAPath                 string   `json:"caPath,omitempty"`
	InsecureSkipTLSVerify  bool     `json:"insecureSkipTLSVerify,omitempty"`
	IdleTimeout            int      `json:"idleTimeout,omitempty"`
}

func sessionOptionsDefaults() SessionOptions {
	return SessionOptions{
		Type: CookieSessionStoreType,
		Cookie: CookieStoreOptions{
			Minimal: false,
		},
	}
}
