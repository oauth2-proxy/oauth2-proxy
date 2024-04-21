package providers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/stretchr/testify/assert"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	internaloidc "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
)

const (
	idToken      = "eyJfoobar123.eyJbaz987.IDToken"
	accessToken  = "eyJfoobar123.eyJbaz987.AccessToken"
	refreshToken = "eyJfoobar123.eyJbaz987.RefreshToken"

	oidcIssuer   = "https://issuer.example.com"
	oidcClientID = "https://test.myapp.com"
	oidcSecret   = "SuperSecret123456789"
	oidcNonce    = "abcde12345edcba09876abcde12345ff"

	failureIssuer = "this-id-fails-verification"
)

var (
	verified   = true
	unverified = false

	registeredClaims = jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{oidcClientID},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(5) * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    oidcIssuer,
		NotBefore: jwt.NewNumericDate(time.Time{}),
		Subject:   "123456789",
	}

	defaultIDToken = idTokenClaims{
		Name:             "Jane Dobbs",
		Email:            "janed@me.com",
		Phone:            "+4798765432",
		Picture:          "http://mugbook.com/janed/me.jpg",
		Groups:           []string{"test:a", "test:b"},
		Roles:            []string{"test:c", "test:d"},
		Verified:         &verified,
		Nonce:            encryption.HashNonce([]byte(oidcNonce)),
		RegisteredClaims: registeredClaims,
	}

	numericGroupsIDToken = idTokenClaims{
		Name:             "Jane Dobbs",
		Email:            "janed@me.com",
		Phone:            "+4798765432",
		Picture:          "http://mugbook.com/janed/me.jpg",
		Groups:           []interface{}{1, 2, 3},
		Roles:            []string{"test:c", "test:d"},
		Verified:         &verified,
		Nonce:            encryption.HashNonce([]byte(oidcNonce)),
		RegisteredClaims: registeredClaims,
	}

	complexGroupsIDToken = idTokenClaims{
		Name:    "Complex Claim",
		Email:   "complex@claims.com",
		Phone:   "+5439871234",
		Picture: "http://mugbook.com/complex/claims.jpg",
		Groups: []interface{}{
			map[string]interface{}{
				"groupId": "Admin Group Id",
				"roles":   []string{"Admin"},
			},
			12345,
			"Just::A::String",
		},
		Roles:            []string{"test:simple", "test:roles"},
		Verified:         &verified,
		RegisteredClaims: registeredClaims,
	}

	unverifiedIDToken = idTokenClaims{
		Name:             "Mystery Man",
		Email:            "unverified@email.com",
		Phone:            "+4025205729",
		Picture:          "http://mugbook.com/unverified/email.jpg",
		Groups:           []string{"test:a", "test:b"},
		Roles:            []string{"test:c", "test:d"},
		Verified:         &unverified,
		RegisteredClaims: registeredClaims,
	}

	minimalIDToken = idTokenClaims{
		RegisteredClaims: registeredClaims,
	}
)

type idTokenClaims struct {
	Name     string      `json:"preferred_username,omitempty"`
	Email    string      `json:"email,omitempty"`
	Phone    string      `json:"phone_number,omitempty"`
	Picture  string      `json:"picture,omitempty"`
	Groups   interface{} `json:"groups,omitempty"`
	Roles    interface{} `json:"roles,omitempty"`
	Verified *bool       `json:"email_verified,omitempty"`
	Nonce    string      `json:"nonce,omitempty"`
	jwt.RegisteredClaims
}

type mockJWKS struct{}

func (mockJWKS) VerifySignature(_ context.Context, jwt string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[1])
	if err != nil {
		return nil, err
	}

	tokenClaims := &idTokenClaims{}
	err = json.Unmarshal(decoded, tokenClaims)
	if err != nil || tokenClaims.Issuer == failureIssuer {
		return nil, fmt.Errorf("the validation failed for subject [%v]", tokenClaims.Subject)
	}

	return decoded, nil
}

func newSignedTestIDToken(tokenClaims idTokenClaims) (string, error) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	standardClaims := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	return standardClaims.SignedString(key)
}

func newTestOauth2Token() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		Expiry:       time.Time{}.Add(time.Duration(5) * time.Second),
	}
}

func TestProviderData_verifyIDToken(t *testing.T) {
	failureIDToken := defaultIDToken
	failureIDToken.Issuer = failureIssuer

	testCases := map[string]struct {
		IDToken       *idTokenClaims
		Verifier      bool
		ExpectIDToken bool
		ExpectedError error
	}{
		"Valid ID Token": {
			IDToken:       &defaultIDToken,
			Verifier:      true,
			ExpectIDToken: true,
			ExpectedError: nil,
		},
		"Missing ID Token": {
			IDToken:       nil,
			Verifier:      true,
			ExpectIDToken: false,
			ExpectedError: ErrMissingIDToken,
		},
		"OIDC Verifier not Configured": {
			IDToken:       &defaultIDToken,
			Verifier:      false,
			ExpectIDToken: false,
			ExpectedError: ErrMissingOIDCVerifier,
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			g := NewWithT(t)

			token := newTestOauth2Token()
			if tc.IDToken != nil {
				idToken, err := newSignedTestIDToken(*tc.IDToken)
				g.Expect(err).ToNot(HaveOccurred())
				token = token.WithExtra(map[string]interface{}{
					"id_token": idToken,
				})
			}

			provider := &ProviderData{}
			if tc.Verifier {
				verificationOptions := internaloidc.IDTokenVerificationOptions{
					AudienceClaims: []string{"aud"},
					ClientID:       oidcClientID,
				}
				provider.Verifier = internaloidc.NewVerifier(oidc.NewVerifier(
					oidcIssuer,
					mockJWKS{},
					&oidc.Config{ClientID: oidcClientID},
				), verificationOptions)
			}
			verified, err := provider.verifyIDToken(context.Background(), token)
			if err != nil {
				g.Expect(err).To(Equal(tc.ExpectedError))
			}

			if tc.ExpectIDToken {
				g.Expect(verified).ToNot(BeNil())
				g.Expect(*verified).To(BeAssignableToTypeOf(oidc.IDToken{}))
			} else {
				g.Expect(verified).To(BeNil())
			}
		})
	}
}

func TestProviderData_buildSessionFromClaims(t *testing.T) {
	testCases := map[string]struct {
		IDToken                  idTokenClaims
		AllowUnverified          bool
		UserClaim                string
		EmailClaim               string
		GroupsClaim              string
		SkipClaimsFromProfileURL bool
		SetProfileURL            bool
		ExpectedError            error
		ExpectedSession          *sessions.SessionState
		ExpectProfileURLCalled   bool
	}{
		"Standard": {
			IDToken:         defaultIDToken,
			AllowUnverified: false,
			EmailClaim:      "email",
			GroupsClaim:     "groups",
			UserClaim:       "sub",
			ExpectedSession: &sessions.SessionState{
				User:              "123456789",
				Email:             "janed@me.com",
				Groups:            []string{"test:a", "test:b"},
				PreferredUsername: "Jane Dobbs",
			},
		},
		"Unverified Denied": {
			IDToken:         unverifiedIDToken,
			AllowUnverified: false,
			EmailClaim:      "email",
			GroupsClaim:     "groups",
			ExpectedError:   errors.New("email in id_token (unverified@email.com) isn't verified"),
		},
		"Unverified Allowed": {
			IDToken:         unverifiedIDToken,
			AllowUnverified: true,
			EmailClaim:      "email",
			GroupsClaim:     "groups",
			UserClaim:       "sub",
			ExpectedSession: &sessions.SessionState{
				User:              "123456789",
				Email:             "unverified@email.com",
				Groups:            []string{"test:a", "test:b"},
				PreferredUsername: "Mystery Man",
			},
		},
		"Complex Groups": {
			IDToken:         complexGroupsIDToken,
			AllowUnverified: true,
			EmailClaim:      "email",
			GroupsClaim:     "groups",
			UserClaim:       "sub",
			ExpectedSession: &sessions.SessionState{
				User:  "123456789",
				Email: "complex@claims.com",
				Groups: []string{
					"{\"groupId\":\"Admin Group Id\",\"roles\":[\"Admin\"]}",
					"12345",
					"Just::A::String",
				},
				PreferredUsername: "Complex Claim",
			},
		},
		"User Claim Switched": {
			IDToken:         defaultIDToken,
			AllowUnverified: true,
			UserClaim:       "phone_number",
			EmailClaim:      "email",
			GroupsClaim:     "groups",
			ExpectedSession: &sessions.SessionState{
				User:              "+4798765432",
				Email:             "janed@me.com",
				Groups:            []string{"test:a", "test:b"},
				PreferredUsername: "Jane Dobbs",
			},
		},
		"User Claim switched to non string": {
			IDToken:         defaultIDToken,
			AllowUnverified: true,
			UserClaim:       "roles",
			EmailClaim:      "email",
			GroupsClaim:     "groups",
			ExpectedSession: &sessions.SessionState{
				User:              "[\"test:c\",\"test:d\"]",
				Email:             "janed@me.com",
				Groups:            []string{"test:a", "test:b"},
				PreferredUsername: "Jane Dobbs",
			},
		},
		"Email Claim Switched": {
			IDToken:         unverifiedIDToken,
			AllowUnverified: true,
			EmailClaim:      "phone_number",
			GroupsClaim:     "groups",
			UserClaim:       "sub",
			ExpectedSession: &sessions.SessionState{
				User:              "123456789",
				Email:             "+4025205729",
				Groups:            []string{"test:a", "test:b"},
				PreferredUsername: "Mystery Man",
			},
		},
		"Email Claim Switched to Non String": {
			IDToken:         unverifiedIDToken,
			AllowUnverified: true,
			EmailClaim:      "roles",
			GroupsClaim:     "groups",
			UserClaim:       "sub",
			ExpectedSession: &sessions.SessionState{
				User:              "123456789",
				Email:             "[\"test:c\",\"test:d\"]",
				Groups:            []string{"test:a", "test:b"},
				PreferredUsername: "Mystery Man",
			},
		},
		"Email Claim Non Existent": {
			IDToken:         unverifiedIDToken,
			AllowUnverified: true,
			EmailClaim:      "aksjdfhjksadh",
			GroupsClaim:     "groups",
			UserClaim:       "sub",
			ExpectedSession: &sessions.SessionState{
				User:              "123456789",
				Email:             "",
				Groups:            []string{"test:a", "test:b"},
				PreferredUsername: "Mystery Man",
			},
		},
		"Groups Claim Switched": {
			IDToken:         defaultIDToken,
			AllowUnverified: false,
			EmailClaim:      "email",
			GroupsClaim:     "roles",
			UserClaim:       "sub",
			ExpectedSession: &sessions.SessionState{
				User:              "123456789",
				Email:             "janed@me.com",
				Groups:            []string{"test:c", "test:d"},
				PreferredUsername: "Jane Dobbs",
			},
		},
		"Groups Claim Non Existent": {
			IDToken:         defaultIDToken,
			AllowUnverified: false,
			EmailClaim:      "email",
			GroupsClaim:     "alskdjfsalkdjf",
			UserClaim:       "sub",
			ExpectedSession: &sessions.SessionState{
				User:              "123456789",
				Email:             "janed@me.com",
				Groups:            nil,
				PreferredUsername: "Jane Dobbs",
			},
		},
		"Groups Claim Numeric values": {
			IDToken:         numericGroupsIDToken,
			AllowUnverified: false,
			EmailClaim:      "email",
			GroupsClaim:     "groups",
			UserClaim:       "sub",
			ExpectedSession: &sessions.SessionState{
				User:              "123456789",
				Email:             "janed@me.com",
				Groups:            []string{"1", "2", "3"},
				PreferredUsername: "Jane Dobbs",
			},
		},
		"Groups Claim string values": {
			IDToken:         defaultIDToken,
			AllowUnverified: false,
			EmailClaim:      "email",
			GroupsClaim:     "email",
			UserClaim:       "sub",
			ExpectedSession: &sessions.SessionState{
				User:              "123456789",
				Email:             "janed@me.com",
				Groups:            []string{"janed@me.com"},
				PreferredUsername: "Jane Dobbs",
			},
		},
		"Request claims from ProfileURL": {
			IDToken:                minimalIDToken,
			SetProfileURL:          true,
			ExpectProfileURLCalled: true,
			ExpectedSession:        &sessions.SessionState{},
		},
		"Skip claims request to ProfileURL": {
			IDToken:                  minimalIDToken,
			SetProfileURL:            true,
			SkipClaimsFromProfileURL: true,
			ExpectedSession:          &sessions.SessionState{},
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			g := NewWithT(t)

			var (
				profileURL       *url.URL
				profileURLCalled bool
			)
			if tc.SetProfileURL {
				profileURLSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					profileURLCalled = true
					w.Write([]byte("{}"))
				}))
				defer profileURLSrv.Close()
				profileURL, _ = url.Parse(profileURLSrv.URL)
			}

			verificationOptions := internaloidc.IDTokenVerificationOptions{
				AudienceClaims: []string{"aud"},
				ClientID:       oidcClientID,
			}
			provider := &ProviderData{
				Verifier: internaloidc.NewVerifier(oidc.NewVerifier(
					oidcIssuer,
					mockJWKS{},
					&oidc.Config{ClientID: oidcClientID},
				), verificationOptions),
				ProfileURL:                 profileURL,
				getAuthorizationHeaderFunc: func(s string) http.Header { return http.Header{} },
			}
			provider.AllowUnverifiedEmail = tc.AllowUnverified
			provider.UserClaim = tc.UserClaim
			provider.EmailClaim = tc.EmailClaim
			provider.GroupsClaim = tc.GroupsClaim
			provider.SkipClaimsFromProfileURL = tc.SkipClaimsFromProfileURL

			rawIDToken, err := newSignedTestIDToken(tc.IDToken)
			g.Expect(err).ToNot(HaveOccurred())

			ss, err := provider.buildSessionFromClaims(rawIDToken, "testtoken")
			if err != nil {
				g.Expect(err).To(Equal(tc.ExpectedError))
			}
			if ss != nil {
				g.Expect(ss).To(Equal(tc.ExpectedSession))
			}
			g.Expect(profileURLCalled).To(Equal(tc.ExpectProfileURLCalled))
		})
	}
}

func TestProviderData_checkNonce(t *testing.T) {
	testCases := map[string]struct {
		Session       *sessions.SessionState
		IDToken       idTokenClaims
		ExpectedError error
	}{
		"Nonces match": {
			Session: &sessions.SessionState{
				Nonce: []byte(oidcNonce),
			},
			IDToken:       defaultIDToken,
			ExpectedError: nil,
		},
		"Nonces do not match": {
			Session: &sessions.SessionState{
				Nonce: []byte("WrongWrongWrong"),
			},
			IDToken:       defaultIDToken,
			ExpectedError: errors.New("id_token nonce claim does not match the session nonce"),
		},

		"Missing nonce claim": {
			Session: &sessions.SessionState{
				Nonce: []byte(oidcNonce),
			},
			IDToken:       minimalIDToken,
			ExpectedError: errors.New("id_token nonce claim does not match the session nonce"),
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			g := NewWithT(t)

			// Ensure that the ID token in the session is valid (signed and contains a nonce)
			// as the nonce claim is extracted to compare with the session nonce
			rawIDToken, err := newSignedTestIDToken(tc.IDToken)
			g.Expect(err).ToNot(HaveOccurred())
			tc.Session.IDToken = rawIDToken

			verificationOptions := internaloidc.IDTokenVerificationOptions{
				AudienceClaims: []string{"aud"},
				ClientID:       oidcClientID,
			}
			provider := &ProviderData{
				Verifier: internaloidc.NewVerifier(oidc.NewVerifier(
					oidcIssuer,
					mockJWKS{},
					&oidc.Config{ClientID: oidcClientID},
				), verificationOptions),
			}

			if err := provider.checkNonce(tc.Session); err != nil {
				g.Expect(err).To(Equal(tc.ExpectedError))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
		})
	}
}

func TestProviderData_loginURLParameters(t *testing.T) {

	testCases := []struct {
		name      string
		overrides url.Values
		has       url.Values
		notHas    []string
	}{
		{
			name:      "no overrides",
			overrides: url.Values{},
			has: url.Values{
				"fixed":             {"fixed-value"},
				"enum_with_default": {"default-value"},
				"free_with_default": {"default-value"},
			},
			notHas: []string{"enum_no_default", "free_no_default"},
		},
		{
			name:      "attempt to override fixed value",
			overrides: url.Values{"fixed": {"another-value"}},
			has: url.Values{
				"fixed":             {"fixed-value"},
				"enum_with_default": {"default-value"},
				"free_with_default": {"default-value"},
			},
			notHas: []string{"enum_no_default", "free_no_default"},
		},
		{
			name: "set one allowed and one forbidden enum",
			overrides: url.Values{
				"enum_no_default": {"allowed1", "not-allowed"},
			},
			has: url.Values{
				"fixed":             {"fixed-value"},
				"enum_with_default": {"default-value"},
				"free_with_default": {"default-value"},
				"enum_no_default":   {"allowed1"},
			},
			notHas: []string{"free_no_default"},
		},
		{
			name:      "replace default value",
			overrides: url.Values{"free_with_default": {"something-else"}},
			has: url.Values{
				"fixed":             {"fixed-value"},
				"enum_with_default": {"default-value"},
				"free_with_default": {"something-else"},
			},
			notHas: []string{"enum_no_default", "free_no_default"},
		},
		{
			name:      "set free text value",
			overrides: url.Values{"free_no_default": {"some-value"}},
			has: url.Values{
				"fixed":             {"fixed-value"},
				"enum_with_default": {"default-value"},
				"free_with_default": {"default-value"},
				"free_no_default":   {"some-value"},
			},
			notHas: []string{"enum_no_default"},
		},
		{
			name:      "attempt to set unapproved parameter",
			overrides: url.Values{"malicious_value": {"evil"}},
			has: url.Values{
				"fixed":             {"fixed-value"},
				"enum_with_default": {"default-value"},
				"free_with_default": {"default-value"},
			},
			notHas: []string{"enum_no_default", "free_no_default"},
		},
	}

	// fixed list of two allowed values
	allowed1 := "allowed1"
	allowed2 := "allowed2"
	allowEnum := []options.URLParameterRule{
		{Value: &allowed1},
		{Value: &allowed2},
	}
	// regex that will allow anything
	anything := "^.*$"
	allowAnything := []options.URLParameterRule{
		{Pattern: &anything},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// set up LoginURLParameters for testing
			data := ProviderData{}
			data.compileLoginParams([]options.LoginURLParameter{
				{Name: "fixed", Default: []string{"fixed-value"}},
				{Name: "enum_with_default", Default: []string{"default-value"}, Allow: allowEnum},
				{Name: "enum_no_default", Allow: allowEnum},
				{Name: "free_with_default", Default: []string{"default-value"}, Allow: allowAnything},
				{Name: "free_no_default", Allow: allowAnything},
			})

			redirectParams := data.LoginURLParams(tc.overrides)
			for _, k := range tc.notHas {
				assert.NotContains(t, redirectParams, k)
			}
			for k, vs := range tc.has {
				actualVals := redirectParams[k]
				assert.ElementsMatch(t, vs, actualVals)
			}
		})
	}
}
