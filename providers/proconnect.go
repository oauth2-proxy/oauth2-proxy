package providers

import (
	"context"
	"encoding/json"

	"github.com/go-jose/go-jose/v3"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

const ProConnectOIDCProviderName = "ProConnect OIDC"

// ProConnectOIDCProvider creates a Keycloak provider based on OIDCProvider
type ProConnectOIDCProvider struct {
	*OIDCProvider
}

// NewProConnectOIDCProvider makes a ProConnectOIDCProvider using the ProviderData
func NewProConnectOIDCProvider(p *ProviderData, opts options.OIDCOptions) *ProConnectOIDCProvider {
	p.setProviderDefaults(providerDefaults{
		name: ProConnectOIDCProviderName,
	})

	provider := &ProConnectOIDCProvider{
		OIDCProvider: NewOIDCProvider(p, opts),
	}

	return provider
}

var _ Provider = (*ProConnectOIDCProvider)(nil)

// EnrichSession is called after Redeem to allow providers to enrich session fields
// such as User, Email, Groups with provider specific API calls.
func (p *ProConnectOIDCProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {

	profileURL := p.ValidateURL.String()
	if p.ProfileURL.String() != "" {
		profileURL = p.ProfileURL.String()
	}

	jwtResponse := requests.New(profileURL).
		WithContext(ctx).
		SetHeader("Authorization", tokenTypeBearer+" "+s.AccessToken).
		Do().Body()

	jws, err := jose.ParseSigned(string(jwtResponse[:]))
	if err != nil {
		logger.Errorf("parse profileURL failed: %v", err)
	}

	// todo: verify the signature
	/*
		payload, err := jws.Verify(s.PublicKey)
		if err != nil {
			return err
		}
	*/

	payload := jws.UnsafePayloadWithoutVerification()

	type EmailData struct {
		Email string `json:"email"`
	}

	var response EmailData
	if err := json.Unmarshal(payload, &response); err != nil {
		return err
	}
	s.Email = response.Email

	return nil
}
