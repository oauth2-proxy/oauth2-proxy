package dpop

import (
	"context"
	"time"
)

// DpopStore defines the interface for storing DPoP JTI (JWT ID) claims
// to prevent replay attacks.
type DpopStore interface {
	// MarkJtiSeen attempts to store a JTI in the store.
	// It returns true if the JTI was successfully inserted (i.e., it was not seen before).
	// It returns false if the JTI was already present in the store (it has been seen).
	// Returns an error if the underlying storage encounters an issue.
	MarkJtiSeen(ctx context.Context, jkt string, jti string, expiresAt time.Time) (bool, error)
}
