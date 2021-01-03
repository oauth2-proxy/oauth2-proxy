package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/bitly/go-simplejson"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// GrafanaProvider represents an Grafana based Identity Provider
type GrafanaProvider struct {
	*ProviderData
}

var _ Provider = (*GrafanaProvider)(nil)

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

func (p *GrafanaProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalJSON()
	if err != nil {
		return fmt.Errorf("error making request: %w", err)
	}

	email, err := p.getEmail(json)
	if err != nil {
		return fmt.Errorf("failed to get email: %w", err)
	}
	s.Email = email

	username, err := p.getUser(json)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	s.PreferredUsername = username

	return nil
}

func (p *GrafanaProvider) getUser(json *simplejson.Json) (string, error) {
	return json.Get("username").String()
}

func (p *GrafanaProvider) getEmail(json *simplejson.Json) (string, error) {
	emailConfirmed, err := json.Get("emailConfirmed").Int()
	if err != nil {
		return "", fmt.Errorf("error confirming email: %w", err)
	}

	if emailConfirmed != 1 {
		return "", fmt.Errorf("skipping unconfirmed email for user")
	}

	email, err := json.Get("email").String()
	if err != nil {
		return "", fmt.Errorf("could not verify email: %w", err)
	}

	return email, nil
}
