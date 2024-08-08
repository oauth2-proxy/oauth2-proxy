package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Jing-ze/oauth2-proxy/pkg/apis/options"
	"github.com/Jing-ze/oauth2-proxy/pkg/apis/sessions"
	"github.com/Jing-ze/oauth2-proxy/pkg/util"

	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
)

// OIDCProvider represents an OIDC based Identity Provider
type OIDCProvider struct {
	*ProviderData

	SkipNonce bool
}

const oidcDefaultScope = "openid email profile"

// NewOIDCProvider initiates a new OIDCProvider
func NewOIDCProvider(p *ProviderData, opts options.OIDCOptions) *OIDCProvider {
	name := "OpenID Connect"

	if p.ProviderName != "" {
		name = p.ProviderName
	}

	oidcProviderDefaults := providerDefaults{
		name:        name,
		loginURL:    nil,
		redeemURL:   nil,
		profileURL:  nil,
		validateURL: nil,
		scope:       oidcDefaultScope,
	}

	if len(p.AllowedGroups) > 0 {
		oidcProviderDefaults.scope += " groups"
	}

	p.setProviderDefaults(oidcProviderDefaults)
	p.getAuthorizationHeaderFunc = makeOIDCHeader

	return &OIDCProvider{
		ProviderData: p,
		SkipNonce:    opts.InsecureSkipNonce,
	}
}

var _ Provider = (*OIDCProvider)(nil)

// GetLoginURL makes the LoginURL with optional nonce support
func (p *OIDCProvider) GetLoginURL(redirectURI, state, nonce string, extraParams url.Values) string {
	if !p.SkipNonce {
		extraParams.Add("nonce", nonce)
	}
	loginURL := makeLoginURL(p.Data(), redirectURI, state, extraParams)
	return loginURL.String()
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *OIDCProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string, client wrapper.HttpClient, callback func(args ...interface{}), timeout uint32) error {
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

	headers := [][2]string{{"Content-Type", "application/x-www-form-urlencoded"}}

	client.Post(p.RedeemURL.String(), headers, []byte(params.Encode()), func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		token, err := util.UnmarshalToken(responseHeaders, responseBody)
		if err != nil {
			util.SendError(err.Error(), nil, http.StatusInternalServerError)
			return
		}
		redeemCallback := func(args ...interface{}) {
			session, err := p.createSession(ctx, token, false)
			if err != nil {
				util.SendError(err.Error(), nil, http.StatusInternalServerError)
				return
			}
			callback(session)
		}
		if _, err := (*p.Verifier.GetKeySet()).VerifySignature(ctx, getIDToken(token)); err != nil {
			(*p.Verifier.GetKeySet()).UpdateKeys(client, timeout, redeemCallback)
		} else {
			redeemCallback()
		}
	}, timeout)

	return nil
}

// EnrichSession is called after Redeem to allow providers to enrich session fields
// such as User, Email, Groups with provider specific API calls.
func (p *OIDCProvider) EnrichSession(_ context.Context, s *sessions.SessionState) error {
	// If a mandatory email wasn't set, error at this point.
	if s.Email == "" {
		return errors.New("neither the id_token nor the profileURL set an email")
	}
	return nil
}

// ValidateSession checks that the session's IDToken is still valid
func (p *OIDCProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	_, err := p.Verifier.Verify(ctx, s.IDToken)
	if err != nil {
		util.Logger.Errorf("id_token verification failed: %v", err)
		return false
	}
	if p.SkipNonce {
		return true
	}
	err = p.checkNonce(s)
	if err != nil {
		util.Logger.Errorf("nonce verification failed: %v", err)
		return false
	}
	return true
}

// RefreshSession uses the RefreshToken to fetch new Access and ID Tokens
func (p *OIDCProvider) RefreshSession(ctx context.Context, s *sessions.SessionState, client wrapper.HttpClient, callback func(args ...interface{}), timeout uint32) (bool, error) {
	if s == nil || s.RefreshToken == "" {
		return false, fmt.Errorf("refresh token is empty")
	}

	err := p.redeemRefreshToken(ctx, s, client, callback, timeout)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	return true, nil
}

// redeemRefreshToken uses a RefreshToken with the RedeemURL to refresh the
// Access Token and (probably) the ID Token.
func (p *OIDCProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState, client wrapper.HttpClient, callback func(args ...interface{}), timeout uint32) error {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("refresh_token", s.RefreshToken)
	params.Add("grant_type", "refresh_token")

	headers := [][2]string{{"Content-Type", "application/x-www-form-urlencoded"}}

	client.Post(p.RedeemURL.String(), headers, []byte(params.Encode()), func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		token, err := util.UnmarshalToken(responseHeaders, responseBody)
		if err != nil {
			util.SendError(err.Error(), nil, http.StatusInternalServerError)
			return
		}
		redeemRefreshCallBack := func(args ...interface{}) {
			newSession, err := p.createSession(ctx, token, true)
			if err != nil {
				util.SendError(err.Error(), nil, http.StatusInternalServerError)
				return
			}
			// It's possible that if the refresh token isn't in the token response the
			// session will not contain an id token.
			// If it doesn't it's probably better to retain the old one
			if newSession.IDToken != "" {
				s.IDToken = newSession.IDToken
				s.Email = newSession.Email
				s.User = newSession.User
				s.Groups = newSession.Groups
				s.PreferredUsername = newSession.PreferredUsername
			}
			s.AccessToken = newSession.AccessToken
			if newSession.RefreshToken != "" {
				s.RefreshToken = newSession.RefreshToken
			}
			s.CreatedAt = newSession.CreatedAt
			s.ExpiresOn = newSession.ExpiresOn
			callback(s, true)
		}
		if _, err := (*p.Verifier.GetKeySet()).VerifySignature(ctx, getIDToken(token)); err != nil {
			(*p.Verifier.GetKeySet()).UpdateKeys(client, timeout, redeemRefreshCallBack)
		} else {
			redeemRefreshCallBack()
		}
	}, timeout)

	return nil
}

// createSession takes an oauth2.Token and creates a SessionState from it.
// It alters behavior if called from Redeem vs Refresh
func (p *OIDCProvider) createSession(ctx context.Context, token *util.Token, refresh bool) (*sessions.SessionState, error) {
	_, err := p.verifyIDToken(ctx, token)
	if err != nil {
		switch err {
		case ErrMissingIDToken:
			// IDToken is mandatory in Redeem but optional in Refresh
			if !refresh {
				return nil, errors.New("token response did not contain an id_token")
			}
		default:
			return nil, fmt.Errorf("could not verify id_token: %v", err)
		}
	}

	rawIDToken := getIDToken(token)
	ss, err := p.buildSessionFromClaims(rawIDToken, token.AccessToken)
	if err != nil {
		return nil, err
	}

	ss.AccessToken = token.AccessToken
	ss.RefreshToken = token.RefreshToken
	ss.IDToken = rawIDToken

	ss.CreatedAtNow()
	ss.SetExpiresOn(token.Expiry)

	return ss, nil
}
