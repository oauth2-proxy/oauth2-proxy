package providers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
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

	failureTokenID = "this-id-fails-verification"
)

var (
	verified   = true
	unverified = false

	standardClaims = jwt.StandardClaims{
		Audience:  oidcClientID,
		ExpiresAt: time.Now().Add(time.Duration(5) * time.Minute).Unix(),
		Id:        "id-some-id",
		IssuedAt:  time.Now().Unix(),
		Issuer:    oidcIssuer,
		NotBefore: 0,
		Subject:   "123456789",
	}

	defaultIDToken = idTokenClaims{
		Name:           "Jane Dobbs",
		Email:          "janed@me.com",
		Phone:          "+4798765432",
		Picture:        "http://mugbook.com/janed/me.jpg",
		Groups:         []string{"test:a", "test:b"},
		Roles:          []string{"test:c", "test:d"},
		Verified:       &verified,
		Nonce:          encryption.HashNonce([]byte(oidcNonce)),
		StandardClaims: standardClaims,
	}

	complexGroupsIDToken = idTokenClaims{
		Name:    "Complex Claim",
		Email:   "complex@claims.com",
		Phone:   "+5439871234",
		Picture: "http://mugbook.com/complex/claims.jpg",
		Groups: []map[string]interface{}{
			{
				"groupId": "Admin Group Id",
				"roles":   []string{"Admin"},
			},
		},
		Roles:          []string{"test:simple", "test:roles"},
		Verified:       &verified,
		StandardClaims: standardClaims,
	}

	unverifiedIDToken = idTokenClaims{
		Name:           "Mystery Man",
		Email:          "unverified@email.com",
		Phone:          "+4025205729",
		Picture:        "http://mugbook.com/unverified/email.jpg",
		Groups:         []string{"test:a", "test:b"},
		Roles:          []string{"test:c", "test:d"},
		Verified:       &unverified,
		StandardClaims: standardClaims,
	}

	minimalIDToken = idTokenClaims{
		StandardClaims: standardClaims,
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
	jwt.StandardClaims
}

type mockJWKS struct{}

func (mockJWKS) VerifySignature(_ context.Context, jwt string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[1])
	if err != nil {
		return nil, err
	}

	tokenClaims := &idTokenClaims{}
	err = json.Unmarshal(decoded, tokenClaims)
	if err != nil || tokenClaims.Id == failureTokenID {
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
	failureIDToken.Id = failureTokenID

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
		"Invalid ID Token": {
			IDToken:       &failureIDToken,
			Verifier:      true,
			ExpectIDToken: false,
			ExpectedError: errors.New("failed to verify signature: the validation failed for subject [123456789]"),
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
				provider.Verifier = oidc.NewVerifier(
					oidcIssuer,
					mockJWKS{},
					&oidc.Config{ClientID: oidcClientID},
				)
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
		IDToken         idTokenClaims
		AllowUnverified bool
		UserClaim       string
		EmailClaim      string
		GroupsClaim     string
		ExpectedError   error
		ExpectedSession *sessions.SessionState
	}{
		"Standard": {
			IDToken:         defaultIDToken,
			AllowUnverified: false,
			EmailClaim:      "email",
			GroupsClaim:     "groups",
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
			ExpectedSession: &sessions.SessionState{
				User:              "123456789",
				Email:             "complex@claims.com",
				Groups:            []string{"{\"groupId\":\"Admin Group Id\",\"roles\":[\"Admin\"]}"},
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
		"User Claim Invalid": {
			IDToken:         defaultIDToken,
			AllowUnverified: true,
			UserClaim:       "groups",
			EmailClaim:      "email",
			GroupsClaim:     "groups",
			ExpectedError:   errors.New("unable to extract custom UserClaim (groups)"),
		},
		"Email Claim Switched": {
			IDToken:         unverifiedIDToken,
			AllowUnverified: true,
			EmailClaim:      "phone_number",
			GroupsClaim:     "groups",
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
			ExpectedSession: &sessions.SessionState{
				User:              "123456789",
				Email:             "[test:c test:d]",
				Groups:            []string{"test:a", "test:b"},
				PreferredUsername: "Mystery Man",
			},
		},
		"Email Claim Non Existent": {
			IDToken:         unverifiedIDToken,
			AllowUnverified: true,
			EmailClaim:      "aksjdfhjksadh",
			GroupsClaim:     "groups",
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
			ExpectedSession: &sessions.SessionState{
				User:              "123456789",
				Email:             "janed@me.com",
				Groups:            nil,
				PreferredUsername: "Jane Dobbs",
			},
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			g := NewWithT(t)

			provider := &ProviderData{
				Verifier: oidc.NewVerifier(
					oidcIssuer,
					mockJWKS{},
					&oidc.Config{ClientID: oidcClientID},
				),
			}
			provider.AllowUnverifiedEmail = tc.AllowUnverified
			provider.UserClaim = tc.UserClaim
			provider.EmailClaim = tc.EmailClaim
			provider.GroupsClaim = tc.GroupsClaim

			rawIDToken, err := newSignedTestIDToken(tc.IDToken)
			g.Expect(err).ToNot(HaveOccurred())

			idToken, err := provider.Verifier.Verify(context.Background(), rawIDToken)
			g.Expect(err).ToNot(HaveOccurred())

			ss, err := provider.buildSessionFromClaims(idToken)
			if err != nil {
				g.Expect(err).To(Equal(tc.ExpectedError))
			}
			if ss != nil {
				g.Expect(ss).To(Equal(tc.ExpectedSession))
			}
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

			provider := &ProviderData{
				Verifier: oidc.NewVerifier(
					oidcIssuer,
					mockJWKS{},
					&oidc.Config{ClientID: oidcClientID},
				),
			}

			rawIDToken, err := newSignedTestIDToken(tc.IDToken)
			g.Expect(err).ToNot(HaveOccurred())

			idToken, err := provider.Verifier.Verify(context.Background(), rawIDToken)
			g.Expect(err).ToNot(HaveOccurred())

			err = provider.checkNonce(tc.Session, idToken)
			if err != nil {
				g.Expect(err).To(Equal(tc.ExpectedError))
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
		})
	}
}

func TestProviderData_extractGroups(t *testing.T) {
	testCases := map[string]struct {
		Claims         map[string]interface{}
		GroupsClaim    string
		ExpectedGroups []string
	}{
		"Standard String Groups": {
			Claims: map[string]interface{}{
				"email":  "this@does.not.matter.com",
				"groups": []interface{}{"three", "string", "groups"},
			},
			GroupsClaim:    "groups",
			ExpectedGroups: []string{"three", "string", "groups"},
		},
		"Different Claim Name": {
			Claims: map[string]interface{}{
				"email": "this@does.not.matter.com",
				"roles": []interface{}{"three", "string", "roles"},
			},
			GroupsClaim:    "roles",
			ExpectedGroups: []string{"three", "string", "roles"},
		},
		"Numeric Groups": {
			Claims: map[string]interface{}{
				"email":  "this@does.not.matter.com",
				"groups": []interface{}{1, 2, 3},
			},
			GroupsClaim:    "groups",
			ExpectedGroups: []string{"1", "2", "3"},
		},
		"Complex Groups": {
			Claims: map[string]interface{}{
				"email": "this@does.not.matter.com",
				"groups": []interface{}{
					map[string]interface{}{
						"groupId": "Admin Group Id",
						"roles":   []string{"Admin"},
					},
					12345,
					"Just::A::String",
				},
			},
			GroupsClaim: "groups",
			ExpectedGroups: []string{
				"{\"groupId\":\"Admin Group Id\",\"roles\":[\"Admin\"]}",
				"12345",
				"Just::A::String",
			},
		},
		"Missing Groups Claim Returns Nil": {
			Claims: map[string]interface{}{
				"email": "this@does.not.matter.com",
			},
			GroupsClaim:    "groups",
			ExpectedGroups: nil,
		},
		"Non List Groups": {
			Claims: map[string]interface{}{
				"email":  "this@does.not.matter.com",
				"groups": "singleton",
			},
			GroupsClaim:    "groups",
			ExpectedGroups: []string{"singleton"},
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			g := NewWithT(t)

			provider := &ProviderData{
				Verifier: oidc.NewVerifier(
					oidcIssuer,
					mockJWKS{},
					&oidc.Config{ClientID: oidcClientID},
				),
			}
			provider.GroupsClaim = tc.GroupsClaim

			groups := provider.extractGroups(tc.Claims)
			if tc.ExpectedGroups != nil {
				g.Expect(groups).To(Equal(tc.ExpectedGroups))
			} else {
				g.Expect(groups).To(BeNil())
			}
		})
	}
}
