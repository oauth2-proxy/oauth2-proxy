package persistence

import (
	"context"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// Store is used for persistent session stores (IE not Cookie)
// Implementing this interface allows it to easily use the persistence.Manager
// for session ticket + encryption details.
type Store interface {
	Save(context.Context, string, []byte, time.Duration) error
	SaveAndEvict(context.Context, string, []byte, string, time.Duration) error
	Load(context.Context, string) ([]byte, error)
	Clear(context.Context, string) error
	Lock(key string) sessions.Lock
	VerifyConnection(context.Context) error
}
