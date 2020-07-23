package persistence

import (
	"context"
	"time"
)

// Store is used for persistent session stores (IE not Cookie)
// Implementing this interface allows it to easily use the persistence.Manager
// for session ticket + encryption details.
type Store interface {
	Save(context.Context, string, []byte, time.Duration) error
	Load(context.Context, string) ([]byte, error)
	Clear(context.Context, string) error
}
