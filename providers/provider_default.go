package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"time"

	"github.com/coreos/go-oidc"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

var _ Provider = (*ProviderData)(nil)

// Redeem provides a default implementation of the OAuth2 token redemption process
func (p *ProviderData) Redeem(ctx context.Context, redirectURL, code string) (s *sessions.SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	resp, err := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do()
	if err != nil {
		return nil, err
	}

	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err == nil {
		s = &sessions.SessionState{
			AccessToken: jsonResponse.AccessToken,
		}
		return
	}

	var v url.Values
	v, err = url.ParseQuery(string(body))
	if err != nil {
		return
	}
	if a := v.Get("access_token"); a != "" {
		created := time.Now()
		s = &sessions.SessionState{AccessToken: a, CreatedAt: &created}
	} else {
		err = fmt.Errorf("no access token found %s", body)
	}
	return
}

// GetLoginURL with typical oauth parameters
func (p *ProviderData) GetLoginURL(redirectURI, state string) string {
	a := *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	if p.AcrValues != "" {
		params.Add("acr_values", p.AcrValues)
	}
	if p.Prompt != "" {
		params.Set("prompt", p.Prompt)
	} else { // Legacy variant of the prompt param:
		params.Set("approval_prompt", p.ApprovalPrompt)
	}
	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	a.RawQuery = params.Encode()
	return a.String()
}

// GetEmailAddress returns the Account email address
func (p *ProviderData) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	return "", errors.New("not implemented")
}

// GetUserName returns the Account username
func (p *ProviderData) GetUserName(ctx context.Context, s *sessions.SessionState) (string, error) {
	return "", errors.New("not implemented")
}

// GetPreferredUsername returns the Account preferred username
func (p *ProviderData) GetPreferredUsername(ctx context.Context, s *sessions.SessionState) (string, error) {
	return "", errors.New("not implemented")
}

// ValidateGroup validates that the provided email exists in the configured provider
// email group(s).
func (p *ProviderData) ValidateGroup(email string) bool {
	return true
}

// ValidateSessionState validates the AccessToken
func (p *ProviderData) ValidateSessionState(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, nil)
}

// RefreshSessionIfNeeded should refresh the user's session if required and
// do nothing if a refresh is not required
func (p *ProviderData) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	return false, nil
}

func (p *ProviderData) CreateSessionStateFromBearerToken(ctx context.Context, rawIDToken string, idToken *oidc.IDToken) (*sessions.SessionState, error) {
	var claims struct {
		Subject           string `json:"sub"`
		Email             string `json:"email"`
		Verified          *bool  `json:"email_verified"`
		PreferredUsername string `json:"preferred_username"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse bearer token claims: %v", err)
	}

	if claims.Email == "" {
		claims.Email = claims.Subject
	}

	if claims.Verified != nil && !*claims.Verified {
		return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
	}

	newSession := &sessions.SessionState{
		Email:             claims.Email,
		User:              claims.Subject,
		PreferredUsername: claims.PreferredUsername,
		AccessToken:       rawIDToken,
		IDToken:           rawIDToken,
		RefreshToken:      "",
		ExpiresOn:         &idToken.Expiry,
	}

	return newSession, nil
}
