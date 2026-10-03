package providers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"golang.org/x/oauth2"
)

// clientAssertionTypeJWTBearer is the RFC 7523 JWT bearer assertion type.
const clientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// UsesClientAssertion reports whether this provider authenticates to the token
// endpoint with a JWT assertion rather than a client secret.
func (p *ProviderData) UsesClientAssertion() bool {
	return p.ClientAssertionFile != ""
}

// GetClientAssertion returns the JWT used as the token request client assertion.
//
// The file is read on each call so externally rotated projected tokens are used
// before the provider rejects an expired assertion.
func (p *ProviderData) GetClientAssertion() (string, error) {
	assertion, err := os.ReadFile(p.ClientAssertionFile) // #nosec G304
	if err != nil {
		logger.Errorf("error reading client assertion file %s: %v", p.ClientAssertionFile, err)
		return "", errors.New("could not read client assertion file")
	}

	return strings.TrimSpace(string(assertion)), nil
}

// tokenEndpointConfig builds the oauth2.Config used for token endpoint
// requests, applying whichever client authentication method is configured.
func (p *ProviderData) tokenEndpointConfig(redirectURL string) (*oauth2.Config, error) {
	c := &oauth2.Config{
		ClientID: p.ClientID,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
	}

	if p.UsesClientAssertion() {
		// Avoid AuthStyleAutoDetect probing Basic auth with an empty secret.
		c.Endpoint.AuthStyle = oauth2.AuthStyleInParams
		return c, nil
	}

	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}
	c.ClientSecret = clientSecret

	return c, nil
}

// clientAuthCodeOptions returns the extra token request parameters needed to
// authenticate this client when redeeming a code with oauth2.Config.Exchange.
// It returns no options when a client secret is used, as oauth2.Config carries
// the secret itself.
func (p *ProviderData) clientAuthCodeOptions() ([]oauth2.AuthCodeOption, error) {
	if !p.UsesClientAssertion() {
		return nil, nil
	}

	assertion, err := p.GetClientAssertion()
	if err != nil {
		return nil, err
	}

	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("client_assertion_type", clientAssertionTypeJWTBearer),
		oauth2.SetAuthURLParam("client_assertion", assertion),
	}, nil
}

// refreshToken exchanges a refresh token for a new token, applying whichever
// client authentication method is configured.
func (p *ProviderData) refreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	if p.UsesClientAssertion() {
		return p.refreshTokenWithClientAssertion(ctx, refreshToken)
	}

	c, err := p.tokenEndpointConfig("")
	if err != nil {
		return nil, err
	}

	t := &oauth2.Token{
		RefreshToken: refreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.TokenSource(ctx, t).Token()
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	return token, nil
}

// refreshTokenWithClientAssertion exchanges a refresh token for a new token,
// authenticating with a client assertion.
//
// oauth2.Config.TokenSource offers no way to add parameters to the refresh
// request, so the request is built here instead.
func (p *ProviderData) refreshTokenWithClientAssertion(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
	assertion, err := p.GetClientAssertion()
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_assertion", assertion)
	params.Add("client_assertion_type", clientAssertionTypeJWTBearer)
	params.Add("refresh_token", refreshToken)
	params.Add("grant_type", "refresh_token")

	return p.requestToken(ctx, params)
}

// requestToken posts params to the token endpoint and builds an oauth2.Token
// from the response.
func (p *ProviderData) requestToken(ctx context.Context, params url.Values) (*oauth2.Token, error) {
	result := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod(http.MethodPost).
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do()

	var token oauth2.Token
	if err := result.UnmarshalInto(&token); err != nil {
		return nil, fmt.Errorf("unable to unmarshal token response: %w", err)
	}

	// oauth2.Token keeps the wire value separate from the computed expiry.
	if token.ExpiresIn != 0 {
		token.Expiry = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}

	// Keep id_token and other provider-specific fields available through Extra.
	var raw map[string]interface{}
	if err := result.UnmarshalInto(&raw); err != nil {
		return nil, fmt.Errorf("unable to unmarshal token response: %w", err)
	}

	return token.WithExtra(raw), nil
}
