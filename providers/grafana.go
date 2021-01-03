package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// GrafanaProvider represents an Grafana based Identity Provider
type GrafanaProvider struct {
	*ProviderData
}

var _ Provider = (*GrafanaProvider)(nil)

// https://?access_type=online&client_id=a339e72afa3a51a5be00&redirect_uri=https://labbbles.grafana.net/login/grafana_com&response_type=code&scope=user:email&state=xjV-CQTPhUZsfWjYKUzhiGC-4xOWPfG_FV6QxC7ZNRo=
const (
	GrafanaProviderName = "Grafana"
	grafanaDefaultScope = "user:email"
)

var (
	grafanaDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "grafana.com",
		Path:   "/oauth2/authorize",
	}

	grafanaDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "grafana.com",
		Path:   "/api/oauth2/token",
	}

	grafanaDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "grafana.com",
		Path:   "/api/profile",
	}
)

// NewGrafanaProvider initiates a new GrafanaProvider
func NewGrafanaProvider(p *ProviderData) *GrafanaProvider {
	p.setProviderDefaults(providerDefaults{
		name:        GrafanaProviderName,
		loginURL:    grafanaDefaultLoginURL,
		redeemURL:   grafanaDefaultRedeemURL,
		profileURL:  grafanaDefaultProfileURL,
		validateURL: grafanaDefaultProfileURL,
		scope:       grafanaDefaultScope,
	})
	return &GrafanaProvider{ProviderData: p}
}


// GetEmailAddress returns the Account email address
func (p *GrafanaProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalJSON()

	if err != nil {
		return "", fmt.Errorf("error making request: %v", err)
	}

	email, err := json.Get("email").String()
	return email, err
}
