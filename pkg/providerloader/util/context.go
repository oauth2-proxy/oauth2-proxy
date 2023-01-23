package util

import (
	"context"

	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

type contextKey string

const providerKey contextKey = "provider"

// extracts provider stored in a context
// returns nil if provider not found
func FromContext(ctx context.Context) providers.Provider {
	t, ok := ctx.Value(providerKey).(providers.Provider)
	if !ok {
		return nil
	}
	return t
}

// stores provider in the context's key value pair
func AppendToContext(ctx context.Context, p providers.Provider) context.Context {
	return context.WithValue(ctx, providerKey, p)
}
