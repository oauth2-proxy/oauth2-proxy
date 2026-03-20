package options

import (
	"time"
)

// DefaultDpopTimeWindow is the default acceptable time window for DPoP proof's iat claim
const DefaultDpopTimeWindow = 30 * time.Second

// DpopOptions holds the configuration for Demonstrating Proof-of-Possession
type DpopOptions struct {
	Enable       bool                  `flag:"enable-dpop-support" cfg:"enable_dpop_support"`
	TimeWindow   time.Duration         `flag:"dpop-time-window" cfg:"dpop_time_window"`
	JtiStoreType string                `flag:"dpop-jti-store-type" cfg:"dpop_jti_store_type"`
	Redis        DpopRedisStoreOptions `cfg:",squash"`
}

// DpopRedisStoreOptions contains configuration options for the DPoP Redis JTI store.
// It is a copy of RedisStoreOptions but with dpop-specific flag and cfg tags.
type DpopRedisStoreOptions struct {
	ConnectionURL          string   `flag:"dpop-redis-connection-url" cfg:"dpop_redis_connection_url"`
	Username               string   `flag:"dpop-redis-username" cfg:"dpop_redis_username"`
	Password               string   `flag:"dpop-redis-password" cfg:"dpop_redis_password"`
	UseSentinel            bool     `flag:"dpop-redis-use-sentinel" cfg:"dpop_redis_use_sentinel"`
	SentinelPassword       string   `flag:"dpop-redis-sentinel-password" cfg:"dpop_redis_sentinel_password"`
	SentinelMasterName     string   `flag:"dpop-redis-sentinel-master-name" cfg:"dpop_redis_sentinel_master_name"`
	SentinelConnectionURLs []string `flag:"dpop-redis-sentinel-connection-urls" cfg:"dpop_redis_sentinel_connection_urls"`
	UseCluster             bool     `flag:"dpop-redis-use-cluster" cfg:"dpop_redis_use_cluster"`
	ClusterConnectionURLs  []string `flag:"dpop-redis-cluster-connection-urls" cfg:"dpop_redis_cluster_connection_urls"`
	CAPath                 string   `flag:"dpop-redis-ca-path" cfg:"dpop_redis_ca_path"`
	InsecureSkipTLSVerify  bool     `flag:"dpop-redis-insecure-skip-tls-verify" cfg:"dpop_redis_insecure_skip_tls_verify"`
	IdleTimeout            int      `flag:"dpop-redis-connection-idle-timeout" cfg:"dpop_redis_connection_idle_timeout"`
}

func (opts DpopRedisStoreOptions) ToRedisStoreOptions() RedisStoreOptions {
	return RedisStoreOptions{
		ConnectionURL:          opts.ConnectionURL,
		Username:               opts.Username,
		Password:               opts.Password,
		UseSentinel:            opts.UseSentinel,
		SentinelPassword:       opts.SentinelPassword,
		SentinelMasterName:     opts.SentinelMasterName,
		SentinelConnectionURLs: opts.SentinelConnectionURLs,
		UseCluster:             opts.UseCluster,
		ClusterConnectionURLs:  opts.ClusterConnectionURLs,
		CAPath:                 opts.CAPath,
		InsecureSkipTLSVerify:  opts.InsecureSkipTLSVerify,
		IdleTimeout:            opts.IdleTimeout,
	}
}

func dpopDefaults() DpopOptions {
	return DpopOptions{
		Enable:       false,
		TimeWindow:   DefaultDpopTimeWindow,
		JtiStoreType: "",
	}
}
