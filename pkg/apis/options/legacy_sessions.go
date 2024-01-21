package options

import (
	"github.com/spf13/pflag"
)

// SessionOptions contains configuration options for the SessionStore providers.
type LegacySessionOptions struct {
	Type   string                   `flag:"session-store-type" cfg:"session_store_type"`
	Cookie LegacyCookieStoreOptions `cfg:",squash"`
	Redis  LegacyRedisStoreOptions  `cfg:",squash"`
}

// CookieStoreOptions contains configuration options for the CookieSessionStore.
type LegacyCookieStoreOptions struct {
	Minimal bool `flag:"session-cookie-minimal" cfg:"session_cookie_minimal"`
}

// RedisStoreOptions contains configuration options for the RedisSessionStore.
type LegacyRedisStoreOptions struct {
	ConnectionURL          string   `flag:"redis-connection-url" cfg:"redis_connection_url"`
	Password               string   `flag:"redis-password" cfg:"redis_password"`
	Username               string   `flag:"redis-username" cfg:"redis_username"`
	UseSentinel            bool     `flag:"redis-use-sentinel" cfg:"redis_use_sentinel"`
	SentinelPassword       string   `flag:"redis-sentinel-password" cfg:"redis_sentinel_password"`
	SentinelMasterName     string   `flag:"redis-sentinel-master-name" cfg:"redis_sentinel_master_name"`
	SentinelConnectionURLs []string `flag:"redis-sentinel-connection-urls" cfg:"redis_sentinel_connection_urls"`
	UseCluster             bool     `flag:"redis-use-cluster" cfg:"redis_use_cluster"`
	ClusterConnectionURLs  []string `flag:"redis-cluster-connection-urls" cfg:"redis_cluster_connection_urls"`
	CAPath                 string   `flag:"redis-ca-path" cfg:"redis_ca_path"`
	InsecureSkipTLSVerify  bool     `flag:"redis-insecure-skip-tls-verify" cfg:"redis_insecure_skip_tls_verify"`
	IdleTimeout            int      `flag:"redis-connection-idle-timeout" cfg:"redis_connection_idle_timeout"`
}

func legacySessionFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("session", pflag.ExitOnError)

	flagSet.String("session-store-type", "cookie", "the session storage provider to use")
	flagSet.Bool("session-cookie-minimal", false, "strip OAuth tokens from cookie session stores if they aren't needed (cookie session store only)")
	flagSet.String("redis-connection-url", "", "URL of redis server for redis session storage (eg: redis://[USER[:PASSWORD]@]HOST[:PORT])")
	flagSet.String("redis-username", "", "Redis username. Applicable for Redis configurations where ACL has been configured. Will override any username set in `--redis-connection-url`")
	flagSet.String("redis-password", "", "Redis password. Applicable for all Redis configurations. Will override any password set in `--redis-connection-url`")
	flagSet.Bool("redis-use-sentinel", false, "Connect to redis via sentinels. Must set --redis-sentinel-master-name and --redis-sentinel-connection-urls to use this feature")
	flagSet.String("redis-sentinel-password", "", "Redis sentinel password. Used only for sentinel connection; any redis node passwords need to use `--redis-password`")
	flagSet.String("redis-sentinel-master-name", "", "Redis sentinel master name. Used in conjunction with --redis-use-sentinel")
	flagSet.String("redis-ca-path", "", "Redis custom CA path")
	flagSet.Bool("redis-insecure-skip-tls-verify", false, "Use insecure TLS connection to redis")
	flagSet.StringSlice("redis-sentinel-connection-urls", []string{}, "List of Redis sentinel connection URLs (eg redis://[USER[:PASSWORD]@]HOST[:PORT]). Used in conjunction with --redis-use-sentinel")
	flagSet.Bool("redis-use-cluster", false, "Connect to redis cluster. Must set --redis-cluster-connection-urls to use this feature")
	flagSet.StringSlice("redis-cluster-connection-urls", []string{}, "List of Redis cluster connection URLs (eg redis://[USER[:PASSWORD]@]HOST[:PORT]). Used in conjunction with --redis-use-cluster")
	flagSet.Int("redis-connection-idle-timeout", 0, "Redis connection idle timeout seconds, if Redis timeout option is non-zero, the --redis-connection-idle-timeout must be less then Redis timeout option")

	return flagSet
}

func (l *LegacySessionOptions) convert() SessionOptions {
	return SessionOptions{
		Type: l.Type,
		Cookie: CookieStoreOptions{
			Minimal: l.Cookie.Minimal,
		},
		Redis: RedisStoreOptions{
			ConnectionURL:          l.Redis.ConnectionURL,
			Password:               l.Redis.Password,
			UseSentinel:            l.Redis.UseSentinel,
			SentinelPassword:       l.Redis.SentinelPassword,
			SentinelMasterName:     l.Redis.SentinelMasterName,
			SentinelConnectionURLs: l.Redis.SentinelConnectionURLs,
			UseCluster:             l.Redis.UseCluster,
			ClusterConnectionURLs:  l.Redis.ClusterConnectionURLs,
			CAPath:                 l.Redis.CAPath,
			InsecureSkipTLSVerify:  l.Redis.InsecureSkipTLSVerify,
			IdleTimeout:            l.Redis.IdleTimeout,
		},
	}
}
