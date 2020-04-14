package providers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
)

func TestRefresh(t *testing.T) {
	p := &ProviderData{}
	ctx := context.TODO()
	refreshed, err := p.RefreshSessionIfNeeded(ctx, &sessions.SessionState{
		ExpiresOn: time.Now().Add(time.Duration(-11) * time.Minute),
	})
	assert.Equal(t, false, refreshed)
	assert.Equal(t, nil, err)
}
