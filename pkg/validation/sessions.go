package validation

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/redis"
)

func validateSessionCookieMinimal(o *options.Options) []string {
	if !o.Session.Cookie.Minimal {
		return []string{}
	}

	msgs := []string{}
	for _, header := range append(o.InjectRequestHeaders, o.InjectResponseHeaders...) {
		for _, value := range header.Values {
			if value.ClaimSource != nil {
				if isSensitiveTokenClaim(value.ClaimSource.Claim) {
					msgs = append(msgs,
						fmt.Sprintf("%s claim for header %q requires oauth tokens in sessions. session_cookie_minimal cannot be set", value.ClaimSource.Claim, header.Name))
				}
			}
		}
	}

	if o.Cookie.Refresh != time.Duration(0) {
		msgs = append(msgs,
			"cookie_refresh > 0 requires oauth tokens in sessions. session_cookie_minimal cannot be set")
	}
	return msgs
}

func isSensitiveTokenClaim(claim string) bool {
	switch strings.TrimSpace(claim) {
	case "access_token", "id_token", "refresh_token":
		return true
	default:
		return false
	}
}

// validateRedisSessionStore builds a Redis Client from the options and
// attempts to connect, Set, Get and Del a random health check key
func validateRedisSessionStore(o *options.Options) []string {
	if o.Session.Type != options.RedisSessionStoreType {
		return []string{}
	}

	client, err := redis.NewRedisClient(o.Session.Redis)
	if err != nil {
		return []string{fmt.Sprintf("unable to initialize a redis client: %v", err)}
	}

	n, err := encryption.Nonce(32)
	if err != nil {
		return []string{fmt.Sprintf("unable to generate a redis initialization test key: %v", err)}
	}
	nonce := base64.RawURLEncoding.EncodeToString(n)

	key := fmt.Sprintf("%s-healthcheck-%s", o.Cookie.Name, nonce)
	return sendRedisConnectionTest(client, key, nonce)
}

func sendRedisConnectionTest(client redis.Client, key string, val string) []string {
	msgs := []string{}
	ctx := context.Background()

	err := client.Set(ctx, key, []byte(val), time.Duration(60)*time.Second)
	if err != nil {
		msgs = append(msgs, fmt.Sprintf("unable to set a redis initialization key: %v", err))
	} else {
		gval, err := client.Get(ctx, key)
		if err != nil {
			msgs = append(msgs,
				fmt.Sprintf("unable to retrieve redis initialization key: %v", err))
		}
		if string(gval) != val {
			msgs = append(msgs,
				"the retrieved redis initialization key did not match the value we set")
		}
	}

	err = client.Del(ctx, key)
	if err != nil {
		msgs = append(msgs, fmt.Sprintf("unable to delete the redis initialization key: %v", err))
	}
	return msgs
}
