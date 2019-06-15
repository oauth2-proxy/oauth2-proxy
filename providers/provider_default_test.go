package providers

import (
	"testing"
	"time"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
)

func TestRefresh(t *testing.T) {
	p := &ProviderData{}
	refreshed, err := p.RefreshSessionIfNeeded(&sessions.SessionState{
		ExpiresOn: time.Now().Add(time.Duration(-11) * time.Minute),
	})
	assert.Equal(t, false, refreshed)
	assert.Equal(t, nil, err)
}
