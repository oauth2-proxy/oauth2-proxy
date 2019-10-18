package providers

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/bitly/go-simplejson"
	oidc "github.com/coreos/go-oidc"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/logger"
	"github.com/pusher/oauth2_proxy/pkg/requests"
	"golang.org/x/oauth2"
)

// AzureProvider represents an Azure based Identity Provider
type AzureProvider struct {
	DefaultProvider
	Tenant string
}

// NewAzureProvider initiates a new AzureProvider
func NewAzureProvider(p *ProviderData) *AzureProvider {
	p.ProviderName = "Azure"

	if p.ProfileURL == nil || p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
			Scheme:   "https",
			Host:     "graph.windows.net",
			Path:     "/me",
			RawQuery: "api-version=1.6",
		}
	}
	if p.ProtectedResource == nil || p.ProtectedResource.String() == "" {
		p.ProtectedResource = &url.URL{
			Scheme: "https",
			Host:   "graph.windows.net",
		}
	}
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
	if p.Scope == "" {
		p.Scope = "openid"
	}

	newProvider := &AzureProvider{DefaultProvider: DefaultProvider{ProviderData: p}}
	newProvider.Redeemer = newProvider
	newProvider.ClaimExporter = newProvider
	newProvider.UserInfoFiller = newProvider
	return newProvider
}

// Configure defaults the AzureProvider configuration options
func (p *AzureProvider) Configure(tenant string) {
	p.Tenant = tenant
	if tenant == "" {
		p.Tenant = "common"
	}

	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + p.Tenant + "/oauth2/authorize"}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + p.Tenant + "/oauth2/token",
		}
	}
	ctx := context.Background()
	keySet := oidc.NewRemoteKeySet(ctx, "https://sts.windows.net/common/discovery/keys")
	p.Verifier = oidc.NewVerifier("https://sts.windows.net/"+p.Tenant+"/", keySet, &oidc.Config{
		ClientID: p.ClientID,
	})

}

// GetEmailAddress returns the Account email address
func (p *AzureProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {
	return p.fillEmail(&oauth2.Token{AccessToken: s.AccessToken})
}

func (p *AzureProvider) fillEmail(token *oauth2.Token) (string, error) {
	var email string
	var err error
	if token.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getAuthHeader(token.AccessToken)

	json, err := requests.Request(req)

	if err != nil {
		return "", err
	}
	email, err = getEmailFromJSON(json)

	if err == nil && email != "" {
		return email, err
	}

	email, err = json.Get("userPrincipalName").String()

	if err != nil {
		logger.Printf("failed making request %s", err)
		return "", err
	}

	if email == "" {
		logger.Printf("failed to get email address")
		return "", err
	}

	return email, err
}

func getEmailFromJSON(json *simplejson.Json) (string, error) {
	var email string
	var err error

	email, err = json.Get("mail").String()

	if err != nil || email == "" {
		otherMails, otherMailsErr := json.Get("otherMails").Array()
		if len(otherMails) > 0 {
			email = otherMails[0].(string)
		}
		err = otherMailsErr
	}

	return email, err
}

func (p *AzureProvider) fillUser(*GenericClaims, *oauth2.Token) string {
	return ""
}

func (p *AzureProvider) getAuthFlowConfig() (c *oauth2.Config) {

	c = &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL:  p.RedeemURL.String(),
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	return
}

func (p *AzureProvider) getAuthFlowConfigWithRedirect(redirectURL string) (c *oauth2.Config) {
	c = p.getAuthFlowConfig()
	c.RedirectURL = redirectURL
	return
}

func (p *AzureProvider) exchangeCodeForToken(ctx context.Context, authConfig *oauth2.Config, code string) (token *oauth2.Token, err error) {
	token, err = authConfig.Exchange(ctx, code, oauth2.SetAuthURLParam("resource", "https://graph.windows.net"))
	return
}

// ValidateSessionState validates the AccessToken
func (p *AzureProvider) ValidateSessionState(s *sessions.SessionState) bool {
	return validateToken(p, s.AccessToken, getAuthHeader(s.AccessToken))
}
