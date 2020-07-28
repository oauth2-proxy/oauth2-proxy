package providers

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
)

func TestRefresh(t *testing.T) {
	p := &ProviderData{}

	expires := time.Now().Add(time.Duration(-11) * time.Minute)
	refreshed, err := p.RefreshSessionIfNeeded(context.Background(), &sessions.SessionState{
		ExpiresOn: &expires,
	})
	assert.Equal(t, false, refreshed)
	assert.Equal(t, nil, err)
}

func TestAcrValuesNotConfigured(t *testing.T) {
	p := &ProviderData{
		LoginURL: &url.URL{
			Scheme: "http",
			Host:   "my.test.idp",
			Path:   "/oauth/authorize",
		},
	}

	result := p.GetLoginURL("https://my.test.app/oauth", "")
	assert.NotContains(t, result, "acr_values")
}

func TestAcrValuesConfigured(t *testing.T) {
	p := &ProviderData{
		LoginURL: &url.URL{
			Scheme: "http",
			Host:   "my.test.idp",
			Path:   "/oauth/authorize",
		},
		AcrValues: "testValue",
	}

	result := p.GetLoginURL("https://my.test.app/oauth", "")
	assert.Contains(t, result, "acr_values=testValue")
}
