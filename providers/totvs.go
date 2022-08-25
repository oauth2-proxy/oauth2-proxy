package providers

import (
	"bytes"
	"context"
	b64 "encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// TOTVSProvider represents a TOTVS based Identity Provider
type TOTVSProvider struct {
	*ProviderData
}

var _ Provider = (*TOTVSProvider)(nil)

const (
	totvsProviderName = "TOTVS"
	totvsDefaultScope = "email"
)

var (
	// Default Login URL for TOTVS.
	totvsDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "app.fluigidentity.com",
		Path:   "/accounts/oauth/authorize",
	}

	// Default Redeem URL for TOTVS.
	totvsDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "api-fluig.totvs.app",
		Path:   "/accounts/oauth/token",
	}

	// Default Profile URL for TOTVS.
	totvsDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "api-fluig.totvs.app",
		Path:   "/manager/api/v1/me",
	}
)

// NewTOTVSProvider initiates a new TOTVSProvider
func NewTOTVSProvider(p *ProviderData) *TOTVSProvider {
	p.setProviderDefaults(providerDefaults{
		name:        totvsProviderName,
		loginURL:    totvsDefaultLoginURL,
		redeemURL:   totvsDefaultRedeemURL,
		profileURL:  totvsDefaultProfileURL,
		validateURL: totvsDefaultProfileURL,
		scope:       totvsDefaultScope,
	})

	return &TOTVSProvider{ProviderData: p}
}

func (p *TOTVSProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	params.Add("response_type", "token")

	authorizationEncoded := b64.StdEncoding.EncodeToString([]byte(p.ClientID + ":" + clientSecret))

	result := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Authorization", "Basic "+authorizationEncoded).
		Do()
	if result.Error() != nil {
		return nil, result.Error()
	}

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresOn    int64  `json:"expires_in"`
	}

	err = result.UnmarshalInto(&jsonResponse)
	if err != nil {
		return nil, fmt.Errorf("no access token found %s", err)
	}

	session := &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		RefreshToken: jsonResponse.RefreshToken,
		IDToken:      jsonResponse.AccessToken, // HACK: This isn't an ID Token, but this is necessary to use skip_jwt_bearer_tokens and pass_authorization_header flags
	}
	session.CreatedAtNow()
	session.SetExpiresOn(time.Unix(jsonResponse.ExpiresOn, 0))
	s, _ := p.buildSessionFromClaims(session.IDToken, session.AccessToken)
	session.Email = s.Email

	return session, nil
}

func (p *TOTVSProvider) GetLoginURL(redirectURI, state, nonce string, extraParams url.Values) string {
	loginURL := *p.LoginURL
	params, _ := url.ParseQuery(loginURL.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	params.Add("grant_type", "authorization_code")

	loginURL.RawQuery = params.Encode()

	return loginURL.String()
}

func (p *TOTVSProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}

func (p *TOTVSProvider) Authorize(ctx context.Context, s *sessions.SessionState) (bool, error) {
	//TODO: Implement requests validations here
	return true, nil
}
