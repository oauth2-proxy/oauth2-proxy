package providers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"

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

	// ErrMissingRefreshToken is returned when a Refresh method is called with an
	// empty refresh token
	ErrMissingRefreshToken = errors.New("missing refresh_token")

	// ErrMissingIDToken is returned when an oidc.Token does not contain the
	// extra `id_token` field for an IDToken.
	ErrMissingIDToken = errors.New("missing id_token")

	// ErrMissingOIDCVerifier is returned when a provider didn't set `Verifier`
	// but an attempt to call `Verifier.Verify` was about to be made.
	ErrMissingOIDCVerifier = errors.New("oidc verifier is not configured")

	_ Provider = (*ProviderData)(nil)
)

// GetLoginURL with typical oauth parameters
// codeChallenge and codeChallengeMethod are the PKCE challenge and method to append to the URL params.
// they will be empty strings if no code challenge should be presented
func (p *ProviderData) GetLoginURL(redirectURI, state, _ string, extraParams url.Values) string {
	loginURL := makeLoginURL(p, redirectURI, state, extraParams)
	return loginURL.String()
}

// Redeem provides a default implementation of the OAuth2 token redemption process
// The codeVerifier is set if a code_verifier parameter should be sent for PKCE
func (p *ProviderData) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {

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
	if codeVerifier != "" {
		params.Add("code_verifier", codeVerifier)
	}
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
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	err = result.UnmarshalInto(&jsonResponse)
	if err == nil {
		return &sessions.SessionState{
			AccessToken:  jsonResponse.AccessToken,
			RefreshToken: jsonResponse.RefreshToken,
		}, nil
	}

	values, err := url.ParseQuery(string(result.Body()))
	if err != nil {
		return nil, err
	}
	// TODO (@NickMeves): Uses OAuth `expires_in` to set an expiration
	if accessToken, refreshToken := values.Get("access_token"), values.Get("refresh_token"); accessToken != "" || refreshToken != "" {
		ss := &sessions.SessionState{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}
		ss.CreatedAtNow()
		return ss, nil
	}

	return nil, fmt.Errorf("no access token or refresh token found %s", result.Body())
}

// Redeem provides a default implementation of the OAuth2 refresh token redemption process
func (p *ProviderData) Refresh(ctx context.Context, refreshToken string) (*sessions.SessionState, error) {
	if refreshToken == "" {
		return nil, ErrMissingRefreshToken
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("refresh_token", refreshToken)
	params.Add("grant_type", "refresh_token")
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
	// TODO (@NickMeves): Uses OAuth `expires_in` to set an expiration
	if token := values.Get("access_token"); token != "" {
		ss := &sessions.SessionState{
			AccessToken: token,
		}
		ss.CreatedAtNow()
		return ss, nil
	}

	return nil, fmt.Errorf("no access token found %s", result.Body())
}

// GetEmailAddress returns the Account email address
// Deprecated: Migrate to EnrichSession
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

// RefreshSession refreshes the user's session
func (p *ProviderData) RefreshSession(_ context.Context, _ *sessions.SessionState) (bool, error) {
	return false, ErrNotImplemented
}

// CreateSessionFromToken converts Bearer IDTokens into sessions
func (p *ProviderData) CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	if p.Verifier != nil {
		return middleware.CreateTokenToSessionFunc(p.Verifier.Verify)(ctx, token)
	}
	return nil, ErrNotImplemented
}

// CreateSessionFromToken converts Bearer IDTokens into sessions
func (p *ProviderData) CreateSessionFromRefreshToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	if p.RedeemURL != nil {
		return p.Refresh(ctx, token)
	}
	return nil, ErrNotImplemented
}
