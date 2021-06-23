package providers

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// ADFSProvider represents an ADFS based Identity Provider
type ADFSProvider struct {
	*OIDCProvider

	skipScope bool
	// Expose for unit testing
	oidcEnrichFunc  func(context.Context, *sessions.SessionState) error
	oidcRefreshFunc func(context.Context, *sessions.SessionState) (bool, error)
}

var _ Provider = (*ADFSProvider)(nil)

const (
	adfsProviderName = "ADFS"
	adfsDefaultScope = "openid email profile"
	adfsSkipScope    = false
	adfsUPNClaim     = "upn"
)

// NewADFSProvider initiates a new ADFSProvider
func NewADFSProvider(p *ProviderData) *ADFSProvider {
	p.setProviderDefaults(providerDefaults{
		name:  adfsProviderName,
		scope: adfsDefaultScope,
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

	oidcProvider := &OIDCProvider{
		ProviderData: p,
		SkipNonce:    true,
	}

	return &ADFSProvider{
		OIDCProvider:    oidcProvider,
		skipScope:       adfsSkipScope,
		oidcEnrichFunc:  oidcProvider.EnrichSession,
		oidcRefreshFunc: oidcProvider.RefreshSession,
	}
}

// Configure defaults the ADFSProvider configuration options
func (p *ADFSProvider) Configure(skipScope bool) {
	p.skipScope = skipScope
}

// GetLoginURL Override to double encode the state parameter. If not query params are lost
// More info here: https://docs.microsoft.com/en-us/powerapps/maker/portals/configure/configure-saml2-settings
func (p *ADFSProvider) GetLoginURL(redirectURI, state, nonce string) string {
	extraParams := url.Values{}
	if !p.SkipNonce {
		extraParams.Add("nonce", nonce)
	}
	loginURL := makeLoginURL(p.Data(), redirectURI, url.QueryEscape(state), extraParams)
	if p.skipScope {
		q := loginURL.Query()
		q.Del("scope")
		loginURL.RawQuery = q.Encode()
	}
	return loginURL.String()
}

// EnrichSession calls the OIDC ProfileURL to backfill any fields missing
// from the claims. If Email is missing, falls back to ADFS `upn` claim.
func (p *ADFSProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	err := p.oidcEnrichFunc(ctx, s)
	if err != nil {
		return err
	}

	if s.Email == "" {
		return p.fallbackUPN(ctx, s)
	}
	return nil
}

// RefreshSession refreshes via the OIDC implementation. If email is missing,
// falls back to ADFS `upn` claim.
func (p *ADFSProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	refreshed, err := p.oidcRefreshFunc(ctx, s)
	if err != nil || s.Email != "" {
		return refreshed, err
	}
	err = p.fallbackUPN(ctx, s)
	return refreshed, err
}

func (p *ADFSProvider) fallbackUPN(ctx context.Context, s *sessions.SessionState) error {
	idToken, err := p.Verifier.Verify(ctx, s.IDToken)
	if err != nil {
		return err
	}
	claims, err := p.getClaims(idToken)
	if err != nil {
		return fmt.Errorf("couldn't extract claims from id_token (%v)", err)
	}
	upn := claims.raw[adfsUPNClaim]
	if upn != nil {
		s.Email = fmt.Sprint(upn)
	}
	return nil
}
