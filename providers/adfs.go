package providers

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// ADFSProvider represents an ADFS based Identity Provider
type ADFSProvider struct {
	*OIDCProvider
	SkipScope bool
}

var _ Provider = (*ADFSProvider)(nil)

const (
	ADFSProviderName = "ADFS"
	ADFSDefaultScope = "openid email profile"
	ADFSSkipScope    = false
)

// NewADFSProvider initiates a new ADFSProvider
func NewADFSProvider(p *ProviderData) *ADFSProvider {

	p.setProviderDefaults(providerDefaults{
		name:  ADFSProviderName,
		scope: ADFSDefaultScope,
	})

	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		resource := p.ProtectedResource.String()
		if !strings.HasSuffix(resource, "/") {
			resource += "/"
		}

		if p.Scope != "" && !strings.HasPrefix(p.Scope, resource) {
			p.Scope = resource + p.Scope
		}
	}

	return &ADFSProvider{
		OIDCProvider: &OIDCProvider{
			ProviderData: p,
			SkipNonce:    true,
		},
		SkipScope: ADFSSkipScope,
	}
}

// Configure defaults the ADFSProvider configuration options
func (p *ADFSProvider) Configure(skipScope bool) {
	p.SkipScope = skipScope
}

// GetLoginURL Override to double encode the state parameter. If not query params are lost
// More info here: https://docs.microsoft.com/en-us/powerapps/maker/portals/configure/configure-saml2-settings
func (p *ADFSProvider) GetLoginURL(redirectURI, state, nonce string) string {
	extraParams := url.Values{}
	if !p.SkipNonce {
		extraParams.Add("nonce", nonce)
	}
	loginURL := makeLoginURL(p.Data(), redirectURI, url.QueryEscape(state), extraParams)
	if p.SkipScope {
		q := loginURL.Query()
		q.Del("scope")
		loginURL.RawQuery = q.Encode()
	}
	return loginURL.String()
}

// EnrichSession to add email
func (p *ADFSProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	if s.Email != "" {
		return nil
	}

	idToken, err := p.Verifier.Verify(ctx, s.IDToken)
	if err != nil {
		return err
	}

	p.EmailClaim = "upn"
	c, err := p.getClaims(idToken)

	if err != nil {
		return fmt.Errorf("couldn't extract claims from id_token (%v)", err)
	}
	s.Email = c.Email

	if s.Email == "" {
		err = errors.New("email not set")
	}

	return err
}
