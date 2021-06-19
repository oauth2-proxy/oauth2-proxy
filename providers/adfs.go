package providers

import (
	"net/url"
	"strings"
)

// ADFSProvider represents an ADFS based Identity Provider
type ADFSProvider struct {
	*OIDCProvider
	skipScope bool
}

var _ Provider = (*ADFSProvider)(nil)

const (
	adfsProviderName = "ADFS"
	adfsDefaultScope = "openid email profile"
	adfsSkipScope    = false
	adfsEmailClaim   = "upn"
)

// NewADFSProvider initiates a new ADFSProvider
func NewADFSProvider(p *ProviderData) *ADFSProvider {
	p.setProviderDefaults(providerDefaults{
		name:  adfsProviderName,
		scope: adfsDefaultScope,
	})
	p.EmailClaim = adfsEmailClaim

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
		skipScope: adfsSkipScope,
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
