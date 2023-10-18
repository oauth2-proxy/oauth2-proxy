package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

func newCidaasProvider(serverURL *url.URL) *CIDAASProvider {
	providerData := &ProviderData{
		ProviderName: "cidaas",
		ClientID:     oidcClientID,
		ClientSecret: oidcSecret,
		LoginURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/login/oauth/authorize"},
		RedeemURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/login/oauth/access_token"},
		ProfileURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/profile"},
		ValidateURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/api"},
		Scope:       "openid profile offline_access",
		EmailClaim:  "email",
		GroupsClaim: "groups",
		Verifier: oidc.NewVerifier(
			oidcIssuer,
			mockJWKS{},
			&oidc.Config{ClientID: oidcClientID},
		),
	}

	p := NewCIDAASProvider(providerData, options.CidaasOptions{})

	return p
}

func newCidaasServer(pathBodyMap map[string][]byte) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, ok := pathBodyMap[r.URL.Path]
		if !ok {
			rw.WriteHeader(404)
			return
		}
		rw.Header().Add("content-type", "application/json")
		_, _ = rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

func newTestCidaasSetup(pathToBodyMap map[string][]byte) (*httptest.Server, *CIDAASProvider) {
	redeemURL, server := newCidaasServer(pathToBodyMap)
	provider := newCidaasProvider(redeemURL)
	return server, provider
}

func TestCidaasProvider_EnrichSession(t *testing.T) {
	testCases := map[string]struct {
		ExistingSession *sessions.SessionState
		EmailClaim      string
		GroupsClaim     string
		FilterGroups    FilterGroups
		ProfileJSON     map[string]interface{}
		ExpectedError   error
		ExpectedSession *sessions.SessionState
	}{
		"Missing Email Only in Profile URL": {
			ExistingSession: &sessions.SessionState{
				User:         "missing.email",
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "email",
			GroupsClaim: "groups",
			ProfileJSON: map[string]interface{}{
				"email": "found@email.com",
			},
			ExpectedError: nil,
			ExpectedSession: &sessions.SessionState{
				User:         "missing.email",
				Email:        "found@email.com",
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
		"Missing Email with Custom Claim": {
			ExistingSession: &sessions.SessionState{
				User:         "missing.email",
				Groups:       []string{"already", "populated"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "weird",
			GroupsClaim: "groups",
			ProfileJSON: map[string]interface{}{
				"weird": "weird@claim.com",
				"groups": []map[string]interface{}{
					{
						"groupId": "CIDAAS_USERS",
						"roles":   []string{"USER"},
					},
				},
				"roles": []string{"USER"},
			},
			ExpectedError: nil,
			ExpectedSession: &sessions.SessionState{
				User:         "missing.email",
				Email:        "weird@claim.com",
				Groups:       []string{"CIDAAS_USERS:USER", "cidaas:USER"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
		"Missing Email not in Profile URL": {
			ExistingSession: &sessions.SessionState{
				User:         "missing.email",
				Groups:       []string{"already", "populated"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "email",
			GroupsClaim: "groups",
			ProfileJSON: map[string]interface{}{
				"groups": []map[string]interface{}{
					{
						"groupId": "CIDAAS_USERS",
						"roles":   []string{"USER"},
					},
				},
				"roles": []string{"USER"},
			},
			ExpectedError: errors.New("neither the id_token nor the profileURL set an email"),
			ExpectedSession: &sessions.SessionState{
				User:         "missing.email",
				Groups:       []string{"CIDAAS_USERS:USER", "cidaas:USER"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
		"Missing Groups": {
			ExistingSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       nil,
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "email",
			GroupsClaim: "groups",
			ProfileJSON: map[string]interface{}{
				"email": "new@thing.com",
				"groups": []map[string]interface{}{
					{
						"groupId": "CIDAAS_USERS",
						"roles":   []string{"USER"},
					},
				},
				"roles": []string{"USER"},
			},
			ExpectedError: nil,
			ExpectedSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       []string{"CIDAAS_USERS:USER", "cidaas:USER"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
		"Empty Groups Claims": {
			ExistingSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       []string{},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "email",
			GroupsClaim: "groups",
			ProfileJSON: map[string]interface{}{
				"email": "new@thing.com",
				"groups": []map[string]interface{}{
					{
						"groupId": "CIDAAS_USERS",
						"roles":   []string{"USER"},
					},
				},
				"roles": []string{"USER"},
			},
			ExpectedError: nil,
			ExpectedSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       []string{"CIDAAS_USERS:USER", "cidaas:USER"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
		"Missing Groups with Custom Claim": {
			ExistingSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       nil,
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "email",
			GroupsClaim: "groups2",
			ProfileJSON: map[string]interface{}{
				"email": "already@populated.com",
				"groups2": []map[string]interface{}{
					{
						"sub":     "aa4980ee-0939-4ea7-b67f-81883f143d39",
						"groupId": "CIDAAS_ADMINS",
						"path":    "/CIDAAS_ADMINS/",
						"roles":   []string{"ADMIN"},
					},
					{
						"sub":       "aa4980ee-0939-4ea7-b67f-81883f143d39",
						"groupId":   "customers",
						"groupType": "Customers",
						"path":      "/customers/",
						"roles": []string{
							"CUSTOMER_ACCOUNT_LOGIN",
							"GROUP_ADMIN",
						},
					},
					{
						"groupId": "CIDAAS_USERS",
						"roles":   []string{"USER"},
					},
				},
				"roles": []string{"USER"},
			},
			ExpectedError: nil,
			ExpectedSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       []string{"CIDAAS_ADMINS:ADMIN", "customers:CUSTOMER_ACCOUNT_LOGIN", "customers:GROUP_ADMIN", "CIDAAS_USERS:USER", "cidaas:USER"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
		"Filter Groups": {
			ExistingSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       nil,
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:   "email",
			GroupsClaim:  "groups2",
			FilterGroups: []string{"customers"},
			ProfileJSON: map[string]interface{}{
				"email": "already@populated.com",
				"groups2": []map[string]interface{}{
					{
						"sub":     "aa4980ee-0939-4ea7-b67f-81883f143d39",
						"groupId": "CIDAAS_ADMINS",
						"path":    "/CIDAAS_ADMINS/",
						"roles":   []string{"ADMIN"},
					},
					{
						"sub":       "aa4980ee-0939-4ea7-b67f-81883f143d39",
						"groupId":   "customers",
						"groupType": "Customers",
						"path":      "/customers/",
						"roles": []string{
							"CUSTOMER_ACCOUNT_LOGIN",
							"GROUP_ADMIN",
						},
					},
					{
						"groupId": "CIDAAS_USERS",
						"roles":   []string{"USER"},
					},
				},
				"roles": []string{"USER"},
			},
			ExpectedError: nil,
			ExpectedSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       []string{"customers:CUSTOMER_ACCOUNT_LOGIN", "customers:GROUP_ADMIN"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
		"Missing Groups String Profile URL Response": {
			ExistingSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       nil,
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "email",
			GroupsClaim: "groups",
			ProfileJSON: map[string]interface{}{
				"groups": []map[string]interface{}{
					{
						"sub":     "aa4980ee-0939-4ea7-b67f-81883f143d39",
						"groupId": "CIDAAS_ADMINS",
						"path":    "/CIDAAS_ADMINS/",
						"roles":   []string{"ADMIN"},
					},
					{
						"sub":       "aa4980ee-0939-4ea7-b67f-81883f143d39",
						"groupId":   "customers",
						"groupType": "Customers",
						"path":      "/customers/",
						"roles": []string{
							"CUSTOMER_ACCOUNT_LOGIN",
							"GROUP_ADMIN",
						},
					},
					{
						"groupId": "CIDAAS_USERS",
						"roles":   []string{"USER"},
					},
				},
				"roles": []string{"USER"},
			},
			ExpectedError: nil,
			ExpectedSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       []string{"CIDAAS_ADMINS:ADMIN", "customers:CUSTOMER_ACCOUNT_LOGIN", "customers:GROUP_ADMIN", "CIDAAS_USERS:USER", "cidaas:USER"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
		"Missing Groups in both Claims and Profile URL": {
			ExistingSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "email",
			GroupsClaim: "groups",
			ProfileJSON: map[string]interface{}{
				"email": "new@thing.com",
			},
			ExpectedError: nil,
			ExpectedSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			path := "/userinfo/"
			jsonResp, err := json.Marshal(tc.ProfileJSON)
			assert.NoError(t, err)

			server, provider := newTestCidaasSetup(map[string][]byte{path: jsonResp})
			provider.ProfileURL, err = url.Parse(fmt.Sprintf("%s%s", server.URL, path))
			assert.NoError(t, err)

			provider.EmailClaim = tc.EmailClaim
			provider.GroupsClaim = tc.GroupsClaim
			provider.FilterGroups = tc.FilterGroups
			defer server.Close()

			err = provider.EnrichSession(context.Background(), tc.ExistingSession)
			assert.Equal(t, tc.ExpectedError, err)
			assert.Equal(t, *tc.ExpectedSession, *tc.ExistingSession)
		})
	}
}

func TestCidaasProvider_RefreshSession(t *testing.T) {
	testCases := map[string]struct {
		ExistingSession   *sessions.SessionState
		EmailClaim        string
		GroupsClaim       string
		ProfileJSON       map[string]interface{}
		RedeemJSON        redeemTokenResponse
		ExpectedRefreshed bool
		ExpectedError     error
		ExpectedEmail     string
		ExpectedUser      string
	}{
		"Refresh session successfully": {
			ExistingSession: &sessions.SessionState{
				User:         "session.is.not.locked",
				Email:        "found@email.com",
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			RedeemJSON: redeemTokenResponse{
				AccessToken:  accessToken,
				ExpiresIn:    10,
				TokenType:    "Bearer",
				RefreshToken: refreshToken,
			},
			ExpectedRefreshed: true,
			ExpectedError:     nil,
			ExpectedEmail:     defaultIDToken.Email,
			ExpectedUser:      defaultIDToken.Subject,
		},
		"Unable to refresh session": {
			ExistingSession: &sessions.SessionState{
				User:         "session.is.unable.to.refresh",
				Email:        "found@email.com",
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			ExpectedRefreshed: false,
			ExpectedError:     fmt.Errorf("unable to redeem refresh token: failed to get token: oauth2: server response missing access_token"),
			ExpectedUser:      "session.is.unable.to.refresh",
			ExpectedEmail:     "found@email.com",
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			idToken, _ := newSignedTestIDToken(defaultIDToken)
			tc.RedeemJSON.IDToken = idToken
			redeemPath := "/token/"
			redeemJSONResp, err := json.Marshal(tc.RedeemJSON)
			assert.NoError(t, err)

			serverURL, server := newCidaasServer(
				map[string][]byte{
					redeemPath: redeemJSONResp,
				})
			provider := newCidaasProvider(serverURL)

			// Disable session enrichment, because we want to focus on refreshing logic
			provider.ProfileURL, err = url.Parse("")
			assert.NoError(t, err)
			provider.RedeemURL, err = url.Parse(fmt.Sprintf("%s%s", server.URL, redeemPath))
			assert.NoError(t, err)

			provider.GroupsClaim = tc.GroupsClaim
			defer server.Close()

			var refreshed bool
			refreshed, err = provider.RefreshSession(context.Background(), tc.ExistingSession)

			assert.Equal(t, tc.ExpectedError, err)
			assert.Equal(t, tc.ExpectedRefreshed, refreshed)
			assert.Equal(t, tc.ExpectedEmail, tc.ExistingSession.Email)
			assert.Equal(t, tc.ExpectedUser, tc.ExistingSession.User)
		})
	}
}
