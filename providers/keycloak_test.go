package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

const (
	keycloakAccessToken  = "eyJKeycloak.eyJAccess.Token"
	keycloakUserinfoPath = "/api/v3/user"

	// Userinfo Test Cases
	tcUIStandard      = "userinfo-standard"
	tcUIFail          = "userinfo-fail"
	tcUISingleGroup   = "userinfo-single-group"
	tcUIMissingEmail  = "userinfo-missing-email"
	tcUIMissingGroups = "userinfo-missing-groups"
)

func testKeycloakProvider(backend *httptest.Server) (*KeycloakProvider, error) {
	p := NewKeycloakProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""})

	if backend != nil {
		bURL, err := url.Parse(backend.URL)
		if err != nil {
			return nil, err
		}
		hostname := bURL.Host

		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
	}

	return p, nil
}

func testKeycloakBackend() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != keycloakUserinfoPath {
				w.WriteHeader(404)
			}

			var err error
			switch r.URL.Query().Get("testcase") {
			case tcUIStandard:
				w.WriteHeader(200)
				_, err = w.Write([]byte(`
					{
						"email": "michael.bland@gsa.gov",
						"groups": [
							"test-grp1",
							"test-grp2"
						]
					}
				`))
			case tcUIFail:
				w.WriteHeader(500)
			case tcUISingleGroup:
				w.WriteHeader(200)
				_, err = w.Write([]byte(`
					{
						"email": "michael.bland@gsa.gov",
						"groups": ["test-grp1"]
					}
				`))
			case tcUIMissingEmail:
				w.WriteHeader(200)
				_, err = w.Write([]byte(`
					{
						"groups": [
							"test-grp1",
							"test-grp2"
						]
					}
				`))
			case tcUIMissingGroups:
				w.WriteHeader(200)
				_, err = w.Write([]byte(`
					{
						"email": "michael.bland@gsa.gov"
					}
				`))
			default:
				w.WriteHeader(404)
			}
			if err != nil {
				panic(err)
			}
		}))
}

var _ = Describe("Keycloak Provider Tests", func() {
	var p *KeycloakProvider
	var b *httptest.Server

	BeforeEach(func() {
		b = testKeycloakBackend()

		var err error
		p, err = testKeycloakProvider(b)
		Expect(err).To(BeNil())
	})

	AfterEach(func() {
		b.Close()
	})

	Context("EnrichSession", func() {
		type enrichSessionTableInput struct {
			testcase       string
			expectedError  error
			expectedEmail  string
			expectedGroups []string
		}

		DescribeTable("should return expected results",
			func(in enrichSessionTableInput) {
				var err error
				p.ValidateURL, err = url.Parse(
					fmt.Sprintf("%s%s?testcase=%s", b.URL, keycloakUserinfoPath, in.testcase),
				)
				Expect(err).To(BeNil())

				session := &sessions.SessionState{AccessToken: keycloakAccessToken}
				err = p.EnrichSession(context.Background(), session)

				if in.expectedError != nil {
					Expect(err).To(Equal(in.expectedError))
				} else {
					Expect(err).To(BeNil())
				}

				Expect(session.Email).To(Equal(in.expectedEmail))

				if in.expectedGroups != nil {
					Expect(session.Groups).To(Equal(in.expectedGroups))
				} else {
					Expect(session.Groups).To(BeNil())
				}
			},
			Entry("email and multiple groups", enrichSessionTableInput{
				testcase:       tcUIStandard,
				expectedError:  nil,
				expectedEmail:  "michael.bland@gsa.gov",
				expectedGroups: []string{"test-grp1", "test-grp2"},
			}),
			Entry("email and single group", enrichSessionTableInput{
				testcase:       tcUISingleGroup,
				expectedError:  nil,
				expectedEmail:  "michael.bland@gsa.gov",
				expectedGroups: []string{"test-grp1"},
			}),
			Entry("email and no groups", enrichSessionTableInput{
				testcase:       tcUIMissingGroups,
				expectedError:  nil,
				expectedEmail:  "michael.bland@gsa.gov",
				expectedGroups: nil,
			}),
			Entry("missing email", enrichSessionTableInput{
				testcase: tcUIMissingEmail,
				expectedError: errors.New(
					"unable to extract email from userinfo endpoint: type assertion to string failed"),
				expectedEmail:  "",
				expectedGroups: []string{"test-grp1", "test-grp2"},
			}),
			Entry("request failure", enrichSessionTableInput{
				testcase:       tcUIFail,
				expectedError:  errors.New(`unexpected status "500": `),
				expectedEmail:  "",
				expectedGroups: nil,
			}),
		)
	})
})

func TestKeycloakProviderDefaults(t *testing.T) {
	p, err := testKeycloakProvider(nil)
	assert.NoError(t, err)
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Keycloak", p.Data().ProviderName)
	assert.Equal(t, "https://keycloak.org/oauth/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://keycloak.org/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://keycloak.org/api/v3/user",
		p.Data().ValidateURL.String())
	assert.Equal(t, "api", p.Data().Scope)
}

func TestNewKeycloakProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewKeycloakProvider(&ProviderData{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("Keycloak"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://keycloak.org/oauth/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://keycloak.org/oauth/token"))
	g.Expect(providerData.ProfileURL.String()).To(Equal(""))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://keycloak.org/api/v3/user"))
	g.Expect(providerData.Scope).To(Equal("api"))
}

func TestKeycloakProviderOverrides(t *testing.T) {
	p := NewKeycloakProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/auth"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/token"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/api/v3/user"},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Keycloak", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/api/v3/user",
		p.Data().ValidateURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}
