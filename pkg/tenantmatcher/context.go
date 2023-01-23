package tenantmatcher

import (
	"context"
)

type contextKey string

const tenantIdKey contextKey = "tenantId"

// extarcts tenantId stored in a context
// returns empty string if tenantId not found
func FromContext(ctx context.Context) string {
	t, ok := ctx.Value(tenantIdKey).(string)
	if !ok {
		return ""
	}
	return t
}

// stores tenantId in the context's key value pair
func AppendToContext(ctx context.Context, tenantId string) context.Context {
	return context.WithValue(ctx, tenantIdKey, tenantId)
}
