package dpop

import (
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessions_redis "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/redis"
)

// NewDpopStore creates a new DpopStore based on the provided options.
func NewDpopStore(opts *options.Options) (DpopStore, error) {
	if !opts.DPoP.Enable {
		return nil, nil
	}

	storeType := opts.DPoP.JtiStoreType
	if storeType == "" {
		if opts.Session.Type == "redis" {
			storeType = "session-redis"
		} else {
			storeType = "memory"
		}
	}

	switch storeType {
	case "memory":
		return NewMemoryDpopStore(), nil
	case "redis":
		client, err := sessions_redis.NewRedisClient(opts.DPoP.Redis.ToRedisStoreOptions())
		if err != nil {
			return nil, fmt.Errorf("error constructing redis client for DPoP: %v", err)
		}
		return NewRedisDpopStore(client), nil
	case "session-redis":
		client, err := sessions_redis.NewRedisClient(opts.Session.Redis)
		if err != nil {
			return nil, fmt.Errorf("error constructing session redis client for DPoP: %v", err)
		}
		return NewRedisDpopStore(client), nil
	default:
		return nil, fmt.Errorf("unknown DPoP JTI store type: %s", storeType)
	}
}
