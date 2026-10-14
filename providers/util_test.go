package providers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/oauth2-proxy/mockoidc"
	. "github.com/onsi/gomega"
	"golang.org/x/oauth2"
)

func Test_makeAuthorizationHeader(t *testing.T) {
	testCases := []struct {
		name         string
		prefix       string
		token        string
		extraHeaders map[string]string
	}{
		{
			name:         "With an empty prefix, token and no additional headers",
			prefix:       "",
			token:        "",
			extraHeaders: nil,
		},
		{
			name:         "With a Bearer token type",
			prefix:       tokenTypeBearer,
			token:        "abcdef",
			extraHeaders: nil,
		},
		{
			name:         "With a Token token type",
			prefix:       tokenTypeToken,
			token:        "123456",
			extraHeaders: nil,
		},
		{
			name:   "With a Bearer token type and Accept application/json",
			prefix: tokenTypeToken,
			token:  "abc",
			extraHeaders: map[string]string{
				acceptHeader: acceptApplicationJSON,
			},
		},
		{
			name:   "With a Bearer token type and multiple headers",
			prefix: tokenTypeToken,
			token:  "123",
			extraHeaders: map[string]string{
				acceptHeader: acceptApplicationJSON,
				"foo":        "bar",
				"key":        "value",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			header := makeAuthorizationHeader(tc.prefix, tc.token, tc.extraHeaders)
			g.Expect(header.Get("Authorization")).To(Equal(fmt.Sprintf("%s %s", tc.prefix, tc.token)))
			for k, v := range tc.extraHeaders {
				g.Expect(header.Get(k)).To(Equal(v))
			}
		})
	}
}

func Test_getIDToken(t *testing.T) {
	const idToken = "eyJfoobar.eyJfoobar.12345asdf"
	g := NewWithT(t)

	token := &oauth2.Token{}
	g.Expect(getIDToken(token)).To(Equal(""))

	extraToken := token.WithExtra(map[string]interface{}{
		"id_token": idToken,
	})
	g.Expect(getIDToken(extraToken)).To(Equal(idToken))
}

func Test_formatGroup(t *testing.T) {
	testCases := map[string]struct {
		rawGroup interface{}
		expected string
	}{
		"String Group": {
			rawGroup: "group",
			expected: "group",
		},
		"Numeric Group": {
			rawGroup: 123,
			expected: "123",
		},
		"Map Group": {
			rawGroup: map[string]string{"id": "1", "name": "Test"},
			expected: "{\"id\":\"1\",\"name\":\"Test\"}",
		},
		"List Group": {
			rawGroup: []string{"First", "Second"},
			expected: "[\"First\",\"Second\"]",
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			g := NewWithT(t)
			formattedGroup, err := formatGroup(tc.rawGroup)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(formattedGroup).To(Equal(tc.expected))
		})
	}
}

func newSigningAlgsIssuerMiddleware(m *mockoidc.MockOIDC, supportedSigningAlgs []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			provider := struct {
				Issuer               string   `json:"issuer"`
				AuthURL              string   `json:"authorization_endpoint"`
				TokenURL             string   `json:"token_endpoint"`
				JWKsURL              string   `json:"jwks_uri"`
				UserInfoURL          string   `json:"userinfo_endpoint"`
				SupportedSigningAlgs []string `json:"id_token_signing_alg_values_supported"`
			}{
				Issuer:               m.Issuer(),
				AuthURL:              m.AuthorizationEndpoint(),
				TokenURL:             m.TokenEndpoint(),
				JWKsURL:              m.JWKSEndpoint(),
				UserInfoURL:          m.UserinfoEndpoint(),
				SupportedSigningAlgs: supportedSigningAlgs,
			}

			data, err := json.Marshal(provider)
			if err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				return
			}

			_, _ = rw.Write(data)
		})
	}
}
