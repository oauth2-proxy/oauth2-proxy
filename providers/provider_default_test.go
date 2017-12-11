package providers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRefresh(t *testing.T) {
	p := &ProviderData{}
	refreshed, err := p.RefreshSessionIfNeeded(&SessionState{
		ExpiresOn: time.Now().Add(time.Duration(-11) * time.Minute),
	})
	assert.Equal(t, false, refreshed)
	assert.Equal(t, nil, err)
}
