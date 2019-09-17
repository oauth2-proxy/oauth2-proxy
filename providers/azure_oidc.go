package providers

import (
	"context"
	"net/url"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/logger"
	"golang.org/x/oauth2"
)

type AzureOIDCProvider struct {
	*OIDCProvider
	PermittedGroups []string
	ExemptedEmails  []string
}

type AzureOIDCClaims struct {
	*OIDCClaims
	Groups []string
}

// NewAzureOIDCProvider initiates a new AzureOIDCProvider
func NewAzureOIDCProvider(p *ProviderData) *AzureOIDCProvider {
	provider := AzureOIDCProvider{
		OIDCProvider: NewOIDCProvider(p),
	}
	provider.ProviderName = "Azure OpenID Connect"
	if p.Scope == "" {
		provider.Scope = "openid email profile"
	}

	if provider.ProfileURL == nil || provider.ProfileURL.String() == "" {
		provider.ProfileURL = &url.URL{
			Scheme: "https",
			Host:   "graph.microsoft.com",
			Path:   "/v1.0/me",
		}
	}

	return &provider
}

func (p *AzureOIDCProvider) GetLoginURL(redirectURI, state string) string {
	var a url.URL
	a = *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "id_token code")
	params.Set("redirect_uri", redirectURI)
	params.Set("response_mode", "form_post")
	params.Add("scope", p.Scope)
	params.Add("state", state)
	params.Set("prompt", p.ApprovalPrompt)
	params.Set("nonce", randSeq(32))
	a.RawQuery = params.Encode()
	return a.String()
}

func (p *AzureOIDCProvider) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {
	return p.OIDCProvider.Redeem(redirectURL, code)
}

func (p *AzureOIDCProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	return p.OIDCProvider.RefreshSessionIfNeeded(s)
}

func (p *AzureOIDCProvider) redeemRefreshToken(s *sessions.SessionState) (err error) {
	return p.OIDCProvider.redeemRefreshToken(s)
}

func (p *AzureOIDCProvider) createSessionState(ctx context.Context, token *oauth2.Token) (*sessions.SessionState, error) {
	return p.OIDCProvider.createSessionState(ctx, token)
}

func (p *AzureOIDCProvider) ValidateSessionState(s *sessions.SessionState) bool {
	return p.OIDCProvider.ValidateSessionState(s)
}

func (p *AzureOIDCProvider) SetGroupRestriction(groups []string) {
	p.PermittedGroups = groups
}

func (p *AzureOIDCProvider) SetGroupExemptions(exemptedEmails []string) {
	p.ExemptedEmails = exemptedEmails
}

func (p *AzureOIDCProvider) ValidateGroup(session *sessions.SessionState) bool {
	// configuration doesn't restrict access via groups
	if len(p.PermittedGroups) == 0 {
		return true
	}
	for _, exemptedEmail := range p.ExemptedEmails {
		if session.Email == exemptedEmail {
			return true
		}
	}
	var claims AzureOIDCClaims
	err := getClaimFromToken(session.IDToken, &claims)
	if err != nil {
		logger.Printf("error: failed to parse IDToken, %s", err)
		return false
	}
	for tokenGroup := range claims.Groups {
		for permittedGroup := range p.PermittedGroups {
			if tokenGroup == permittedGroup {
				return true
			}
		}
	}

	return false
}
