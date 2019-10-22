package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"reflect"
	//"sort"
	"time"

	oidc "github.com/coreos/go-oidc"
	//"github.com/davecgh/go-spew/spew"
	//"github.com/mozillazg/go-httpheader"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"golang.org/x/oauth2"
)

// OIDCProvider represents an OIDC based Identity Provider
type OIDCProvider struct {
	*ProviderData

	Verifier             *oidc.IDTokenVerifier
	AllowUnverifiedEmail bool
}

// NewOIDCProvider initiates a new OIDCProvider
func NewOIDCProvider(p *ProviderData) *OIDCProvider {
	p.ProviderName = "OpenID Connect"
	return &OIDCProvider{ProviderData: p}
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *OIDCProvider) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {
	ctx := context.Background()
	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
	}
	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %v", err)
	}
	s, err = p.createSessionState(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("unable to update session: %v", err)
	}

	if p.ProfileURL.String() != "" {
		p.getUserInfo(ctx, token, s)
	}

	return
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new ID token if required
func (p *OIDCProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	origExpiration := s.ExpiresOn

	err := p.redeemRefreshToken(s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	fmt.Printf("refreshed id token %s (expired on %s)\n", s, origExpiration)
	return true, nil
}

func (p *OIDCProvider) redeemRefreshToken(s *sessions.SessionState) (err error) {
	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
	}
	ctx := context.Background()
	t := &oauth2.Token{
		RefreshToken: s.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.TokenSource(ctx, t).Token()
	if err != nil {
		return fmt.Errorf("failed to get token: %v", err)
	}
	newSession, err := p.createSessionState(ctx, token)
	if err != nil {
		return fmt.Errorf("unable to update session: %v", err)
	}

	s.AccessToken = newSession.AccessToken
	s.IDToken = newSession.IDToken
	s.RefreshToken = newSession.RefreshToken
	s.CreatedAt = newSession.CreatedAt
	s.ExpiresOn = newSession.ExpiresOn
	s.Email = newSession.Email
	return
}

func (p *OIDCProvider) getUserInfo(ctx context.Context, token *oauth2.Token, s *sessions.SessionState) error {
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return err
	}
	token.SetAuthHeader(req)
	//req.Header = getOIDCHeader(token.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	claims := StandardClaims{}
	err = json.Unmarshal(body, &claims)
	if err != nil {
		return err
	}
	s.UserInfo = string(body)

	// If the userinfo endpoint profileURL is defined, then there is a chance the userinfo
	// contents at the profileURL contains the email.
	// Make a query to the userinfo endpoint, and attempt to locate the email from there.
	if s.Email == "" {
		if claims.Email != nil {
			return fmt.Errorf("userinfo did not have email: %v", err)
		}
		s.Email = *claims.Email
	}

	if !p.AllowUnverifiedEmail && (claims.EmailVerified == nil || !*claims.EmailVerified) {
		return fmt.Errorf("email in id_token (%s) isn't verified", *claims.Email)
	}
	return nil
}

func (p *OIDCProvider) createSessionState(ctx context.Context, token *oauth2.Token) (*sessions.SessionState, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("token response did not contain an id_token")
	}

	// Parse and verify ID Token payload.
	idToken, err := p.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}

	// Extract standard claims.
	claims := StandardClaims{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}

	// Technically, email is optional.
	email := ""
	if claims.Email != nil && *claims.Email != "" {
		email = *claims.Email
	}
	return &sessions.SessionState{
		AccessToken:  token.AccessToken,
		IDToken:      rawIDToken,
		RefreshToken: token.RefreshToken,
		CreatedAt:    time.Now(),
		ExpiresOn:    idToken.Expiry,
		Email:        email,
		User:         idToken.Subject,
	}, nil
}

// ValidateSessionState checks that the session's IDToken is still valid
func (p *OIDCProvider) ValidateSessionState(s *sessions.SessionState) bool {
	ctx := context.Background()
	_, err := p.Verifier.Verify(ctx, s.IDToken)
	if err != nil {
		return false
	}

	return true
}

// valueString returns the string representation of a value.
func valueString(v reflect.Value) string {
	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}

	if v.Kind() == reflect.Bool {
		if v.Bool() {
			return "1"
		}
		return "0"
	}

	if v.Type() == reflect.TypeOf(time.Time{}) {
		t := v.Interface().(time.Time)
		return t.Format(http.TimeFormat)
	}

	return fmt.Sprint(v.Interface())
}

func reflectValue(header http.Header, val reflect.Value) error {
	var embedded []reflect.Value

	iter := val.MapRange()
	for iter.Next() {
		name := iter.Key().String()
		sv := iter.Value()

		switch t := sv.Interface().(type) {
		case int:
			//log.Printf("%s => %s", name, string(t))
			header.Add(name, string(t))
			continue
		case float64:
			if name == "exp" || name == "nbf" || name == "iat" {
				// well-known time entries
				sec, dec := math.Modf(t)
				vv := time.Unix(int64(sec), int64(dec*1e9))
				header.Add(name, vv.Format(http.TimeFormat))
			} else {
				header.Add(name, fmt.Sprintf("%f", t))
			}
			continue
		case string:
			//log.Printf("%s => %v", name, t)
			header.Add(name, t)
			continue
		case bool:
			//log.Printf("%s => %v", name, t)
			if t {
				header.Add(name, "true")
			} else {
				header.Add(name, "false")
			}
			continue
		case []interface{}: // array
			for _, item := range t {
				vv := valueString(reflect.ValueOf(item))
				//log.Printf("%s[%d] ==> %s", name, i, vv)
				header.Add(name, vv)
			}
			continue
		case map[string]interface{}: // map
			//log.Printf("%s => %v", name, t)
			for key, item := range t {
				vv := valueString(reflect.ValueOf(item))
				//log.Printf("%s[%s] ==> %s", name, key, vv)
				header.Add(fmt.Sprintf("%s_%s", name, key), vv)
			}
			continue
		default:
			log.Printf("%s unknown cast => %v", name, t)
			continue
		}
	}

	for _, f := range embedded {
		if err := reflectValue(header, f); err != nil {
			return err
		}
	}

	return nil
}

// HeadersToInject processes the OIDC session and publishes a set of headers to export to upstreams
func (p *OIDCProvider) HeadersToInject(s *sessions.SessionState) (*http.Header, error) {
	ctx := context.Background()
	if s.IDToken == "" {
		// TODO: IDToken is not set likely because there is no Cipher set in the Session. fallback to previous behavior of passing user & email.
		log.Printf("Encrypted storage not available, exports restricted")
		return p.ProviderData.HeadersToInject(s)
	}
	token, err := p.Verifier.Verify(ctx, s.IDToken)
	if err != nil {
		return nil, fmt.Errorf("Unable to verify session token: %v", err)
	}

	// Get ID claims
	//	idClaims := StandardClaims{}
	var idClaims map[string]interface{}
	token.Claims(&idClaims)
	h := http.Header{}
	val := reflect.ValueOf(idClaims)
	reflectValue(h, val)
	//h, err := httpheader.Header(idClaims)
	//if err != nil {
	//	return nil, fmt.Errorf("Unable to serialize id claims: %v", err)
	//}

	// Get UserInfo Claims
	var userClaims map[string]interface{}
	err = json.Unmarshal([]byte(s.UserInfo), &userClaims)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse userinfo: %v", err)
	}
	userVal := reflect.ValueOf(userClaims)
	hU := http.Header{}
	reflectValue(hU, userVal)

	// Merge the maps
	for k, v := range hU {
		h[k] = v
	}
	// hUser, err := httpheader.Header(userClaims)
	// if err != nil {
	// 	return nil, fmt.Errorf("Unable to serialize userinfo claims: %v", err)
	// }
	//
	// // Merge UserInfo claims
	// for key, values := range hUser {
	// 	_, ok := h[key]
	// 	if ok {
	// 		continue
	// 	}
	// 	for _, v := range values {
	// 		h.Add(key, v)
	// 	}
	// }
	// spew.Dump(h)
	return &h, err
}
