package providers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Jing-ze/oauth2-proxy/pkg/apis/sessions"
	"github.com/Jing-ze/oauth2-proxy/pkg/util"

	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
)

var (
	// ErrNotImplemented is returned when a provider did not override a default
	// implementation method that doesn't have sensible defaults
	ErrNotImplemented = errors.New("not implemented")

	// ErrMissingCode is returned when a Redeem method is called with an empty
	// code
	ErrMissingCode = errors.New("missing code")

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
func (p *ProviderData) Redeem(ctx context.Context, redirectURL, code, codeVerifier string, client wrapper.HttpClient, callback func(args ...interface{}), timeout uint32) error {
	if code == "" {
		return ErrMissingCode
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
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

	req, err := http.NewRequest("POST", p.RedeemURL.String(), strings.NewReader(params.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var headerArray [][2]string
	for key, values := range req.Header {
		if len(values) > 0 {
			headerArray = append(headerArray, [2]string{key, values[0]})
		}
	}
	bodyBytes, err := io.ReadAll(req.Body)
	req.Body.Close()

	client.Post(p.RedeemURL.String(), headerArray, bodyBytes, func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		token, err := util.UnmarshalToken(responseHeaders, responseBody)
		if err != nil {
			util.SendError(err.Error(), nil, http.StatusInternalServerError)
			return
		}
		session := &sessions.SessionState{
			AccessToken: token.AccessToken,
		}
		callback(session)
	}, timeout)
	return nil
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
	return true
}

// RefreshSession refreshes the user's session
func (p *ProviderData) RefreshSession(_ context.Context, _ *sessions.SessionState, client wrapper.HttpClient, callback func(args ...interface{}), timeout uint32) (bool, error) {
	return false, ErrNotImplemented
}
