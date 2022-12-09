package tenant

import (
	"context"

	"github.com/oauth2-proxy/oauth2-proxy/v7/tenant/types"
)

type contextKey string

const tenantKey contextKey = "tenant"

// extarcts tenant stored in a context
// returns nil if tenant not found
func FromContext(ctx context.Context) *types.Tenant {
	t, ok := ctx.Value(tenantKey).(*types.Tenant)
	if !ok {
		return nil
	}
	return t
}

// stores tenant in the context's key value pair
func AppendToContext(ctx context.Context, t *types.Tenant) context.Context {
	return context.WithValue(ctx, tenantKey, t)
}
