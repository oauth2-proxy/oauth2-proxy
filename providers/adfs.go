package providers

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
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
	adfsUPNClaim     = "upn"
)

// NewADFSProvider initiates a new ADFSProvider
func NewADFSProvider(p *ProviderData, opts options.ADFSOptions) *ADFSProvider {
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

	oidcProvider := NewOIDCProvider(p, options.OIDCOptions{InsecureSkipNonce: false})

	return &ADFSProvider{
		OIDCProvider:    oidcProvider,
		skipScope:       opts.SkipScope,
		oidcEnrichFunc:  oidcProvider.EnrichSession,
		oidcRefreshFunc: oidcProvider.RefreshSession,
	}
}

// GetLoginURL Override to double encode the state parameter. If not query params are lost
// More info here: https://docs.microsoft.com/en-us/powerapps/maker/portals/configure/configure-saml2-settings
func (p *ADFSProvider) GetLoginURL(redirectURI, state, nonce string, extraParams url.Values) string {
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
	if err != nil || s.Email == "" {
		// OIDC only errors if email is missing
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
	claims, err := p.getClaimExtractor(s.IDToken, s.AccessToken)
	if err != nil {
		return fmt.Errorf("could not extract claims: %v", err)
	}

	upn, found, err := claims.GetClaim(adfsUPNClaim)
	if err != nil {
		return fmt.Errorf("could not extract %s claim: %v", adfsUPNClaim, err)
	}

	if found && fmt.Sprint(upn) != "" {
		s.Email = fmt.Sprint(upn)
	}
	return nil
}
