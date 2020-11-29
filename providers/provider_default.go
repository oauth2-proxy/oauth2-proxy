package providers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

var (
	// ErrNotImplemented is returned when a provider did not override a default
	// implementation method that doesn't have sensible defaults
	ErrNotImplemented = errors.New("not implemented")

	// ErrMissingCode is returned when a Redeem method is called with an empty
	// code
	ErrMissingCode = errors.New("missing code")

	_ Provider = (*ProviderData)(nil)
)

// Redeem provides a default implementation of the OAuth2 token redemption process
func (p *ProviderData) Redeem(ctx context.Context, redirectURL, code string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
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

	result := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do()
	if result.Error() != nil {
		return nil, result.Error()
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = result.UnmarshalInto(&jsonResponse)
	if err == nil {
		return &sessions.SessionState{
			AccessToken: jsonResponse.AccessToken,
		}, nil
	}

	values, err := url.ParseQuery(string(result.Body()))
	if err != nil {
		return nil, err
	}
	if token := values.Get("access_token"); token != "" {
		created := time.Now()
		return &sessions.SessionState{AccessToken: token, CreatedAt: &created}, nil
	}

	return nil, fmt.Errorf("no access token found %s", result.Body())
}

// GetLoginURL with typical oauth parameters
func (p *ProviderData) GetLoginURL(redirectURI, state string) string {
	extraParams := url.Values{}
	a := makeLoginURL(p, redirectURI, state, extraParams)
	return a.String()
}

// GetEmailAddress returns the Account email address
// DEPRECATED: Migrate to EnrichSession
func (p *ProviderData) GetEmailAddress(_ context.Context, _ *sessions.SessionState) (string, error) {
	return "", ErrNotImplemented
}

// EnrichSession is called after Redeem to allow providers to enrich session fields
// such as User, Email, Groups with provider specific API calls.
func (p *ProviderData) EnrichSession(_ context.Context, _ *sessions.SessionState) error {
	return nil
}

// Authorize performs global authorization on an authenticated session.
// This is not used for fine-grained per route authorization rules.
func (p *ProviderData) Authorize(_ context.Context, s *sessions.SessionState) (bool, error) {
	if len(p.AllowedGroups) == 0 {
		return true, nil
	}

	for _, group := range s.Groups {
		if _, ok := p.AllowedGroups[group]; ok {
			return true, nil
		}
	}

	return false, nil
}

// ValidateSession validates the AccessToken
func (p *ProviderData) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, nil)
}

// RefreshSessionIfNeeded should refresh the user's session if required and
// do nothing if a refresh is not required
func (p *ProviderData) RefreshSessionIfNeeded(_ context.Context, _ *sessions.SessionState) (bool, error) {
	return false, nil
}

// CreateSessionFromToken converts Bearer IDTokens into sessions
func (p *ProviderData) CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	if p.Verifier != nil {
		return middleware.CreateTokenToSessionFunc(p.Verifier.Verify)(ctx, token)
	}
	return nil, ErrNotImplemented
}
