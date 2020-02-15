package providers

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/logger"
)

// DropsolidProvider represents a Dropsolid Platform based Identity Provider
type DropsolidProvider struct {
	*ProviderData
	JWTKey *rsa.PrivateKey
}

type dropsolidJwtClaims struct {
	Scopes []string `json:"scopes"`
	jwt.StandardClaims
}

type dropsolidUserInfo struct {
	UserId string `json:"sub"`
	Email  string `json:"email"`
}

// NewDropsolidProvider initiates a new DropsolidProvider
func NewDropsolidProvider(p *ProviderData) *DropsolidProvider {
	p.ProviderName = "Dropsolid"

	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{Scheme: "https",
			Host: "platform.dropsolid.com",
			Path: "/oauth/authorize",
		}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{Scheme: "https",
			Host: "platform.dropsolid.com",
			Path: "/oauth/token",
		}
	}
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{Scheme: "https",
			Host: "platform.dropsolid.com",
			Path: "/oauth/user.info",
		}
	}

	if p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}

	if p.Scope == "" {
		p.Scope = "openid email"
	}
	return &DropsolidProvider{ProviderData: p}
}

func getDropsolidHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

func (p *DropsolidProvider) getUserInfo(s *sessions.SessionState) (*dropsolidUserInfo, error) {
	// Retrieve user info JSON
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform user info request: %v", err)
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read user info response: %v", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("got %d during user info request: %s", resp.StatusCode, body)
	}

	var userInfo dropsolidUserInfo
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user info: %v", err)
	}
	// handle json did not match error
	if userInfo.UserId == "" || userInfo.Email == "" {
		return nil, fmt.Errorf("failed to parse user info: %v", err)
	}

	return &userInfo, nil
}

// GetUserName returns the Account user name
func (p *DropsolidProvider) GetUserName(s *sessions.SessionState) (string, error) {
	// Retrieve user info
	userInfo, err := p.getUserInfo(s)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve user info: %v", err)
	}

	return userInfo.UserId, nil
}

// GetEmailAddress returns the Account email address
func (p *DropsolidProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {
	// Retrieve user info
	userInfo, err := p.getUserInfo(s)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve user info: %v", err)
	}

	return userInfo.Email, nil
}

// ValidateSessionState validates the AccessToken
func (p *DropsolidProvider) ValidateSessionState(s *sessions.SessionState) bool {
	return validateToken(p, s.AccessToken, getDropsolidHeader(s.AccessToken))
}

// Redeem provides a Dropsolid implementation of the OAuth2 token redemption process
// which also supports the refresh flow.
func (p *DropsolidProvider) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")

	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
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
		AccessToken  string `json:"access_token"`
		ExpiresIn    int64  `json:"expires_in"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)

	if err != nil {
		return
	}

	// Validate the JWT Token
	c, err := p.validateJwtTokenAndGetClaims(jsonResponse.AccessToken)
	//token, err := jwt.ParseWithClaims(jsonResponse.AccessToken, &dropsolidJwtClaims{}, p.getPublicKeyFromJwtBearerVerfifier)
	// If the JWT validation fails, something is really wrong.
	// Do not allow to continue.
	if err != nil {
		return
	}
	claims := c.(dropsolidJwtClaims)
	if err != nil {
		return
	}
	// Check the expiration date in the JWT
	// Decode the JWT token data.
	//claims := token.Claims.(dropsolidJwtClaims)
	// Check if it needs a refresh based on the JWT expiry date
	t := time.Unix(claims.ExpiresAt, 0)

	if err == nil {
		s = &sessions.SessionState{
			AccessToken:  jsonResponse.AccessToken,
			RefreshToken: jsonResponse.RefreshToken,
			CreatedAt:    time.Now(),
			ExpiresOn:    t,
		}
		return
	}

	var v url.Values
	v, err = url.ParseQuery(string(body))
	if err != nil {
		return
	}
	if a := v.Get("access_token"); a != "" {
		s = &sessions.SessionState{AccessToken: a, CreatedAt: time.Now()}
	} else {
		err = fmt.Errorf("no access token found %s", body)
	}
	return
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new ID token if required
func (p *DropsolidProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	// do not refresh when there is no session, when the session is not expired or when the token is seen as valid.
	// The session stays valid.
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	newToken, newRefreshToken, err := p.redeemRefreshToken(s.RefreshToken)
	if err != nil {
		return false, err
	}

	// Validate the JWT Token
	c, err := p.validateJwtTokenAndGetClaims(newToken)
	// If the JWT validation fails, something is really wrong.
	// Do not allow to continue.
	if err != nil {
		return false, err
	}
	claims := c.(*dropsolidJwtClaims)
	if err != nil {
		return false, err
	}
	// Check the expiration date in the JWT
	// Decode the JWT token data.
	t := time.Unix(claims.ExpiresAt, 0)
	origExpiration := s.ExpiresOn
	s.AccessToken = newToken
	s.RefreshToken = newRefreshToken
	s.ExpiresOn = t
	logger.Printf("Refreshed access token %s (expired on %s)", s, origExpiration)

	return true, nil
}

func (p *DropsolidProvider) redeemRefreshToken(refreshToken string) (newToken string, newRefreshToken string, err error) {
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("refresh_token", refreshToken)
	params.Add("grant_type", "refresh_token")
	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
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

	var data struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return
	}
	newToken = data.AccessToken
	newRefreshToken = data.RefreshToken
	// we ignore ExpiresIn in favor of the data in the JWT token.
	return
}

func (p *DropsolidProvider) validateJwtTokenAndGetClaims(rawBearerToken string) (interface{}, error) {
	ctx := context.Background()
	for _, verifier := range p.JwtBearerVerifiers {
		bearerToken, err := verifier.Verify(ctx, rawBearerToken)

		if err != nil {
			logger.Printf("failed to verify bearer token: %v", err)
			continue
		}

		var claims dropsolidJwtClaims
		if err := bearerToken.Claims(&claims); err != nil {
			return nil, fmt.Errorf("failed to parse bearer token claims: %v", err)
		}

		return claims, nil
	}
	return nil, fmt.Errorf("failed to process the raw bearer token or there were no bearer verifiers present")
}

// GetJwtSession loads a session based on a JWT token in the authorization header.
func (p *DropsolidProvider) GetJwtSession(rawBearerToken string) (*sessions.SessionState, error) {
	// Validate the JWT Token
	c, err := p.validateJwtTokenAndGetClaims(rawBearerToken)
	if err != nil {
		return nil, err
	}

	claims := c.(dropsolidJwtClaims)
	if err != nil {
		return nil, err
	}

	// Check the expiration date in the JWT
	t := time.Unix(claims.ExpiresAt, 0)
	session := &sessions.SessionState{
		AccessToken: rawBearerToken,
		CreatedAt:   time.Now(),
		ExpiresOn:   t,
		User:        claims.Subject,
	}

	// Get email address
	email, err := p.GetEmailAddress(session)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve email")
	}
	session.Email = email
	return session, nil
}
