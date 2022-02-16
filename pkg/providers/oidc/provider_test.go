package oidc

import (
	"context"
	"encoding/json"
	"net"
	"net/http"

	"github.com/oauth2-proxy/mockoidc"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Provider", func() {
	type newProviderTableInput struct {
		skipIssuerVerification bool
		expectedError          string
		middlewares            func(*mockoidc.MockOIDC) []func(http.Handler) http.Handler
	}

	DescribeTable("NewProvider", func(in *newProviderTableInput) {
		m, err := mockoidc.NewServer(nil)
		Expect(err).ToNot(HaveOccurred())

		if in.middlewares != nil {
			middlewares := in.middlewares(m)
			for _, middlware := range middlewares {
				m.AddMiddleware(middlware)
			}
		}

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())

		Expect(m.Start(ln, nil)).To(Succeed())
		defer func() {
			Expect(m.Shutdown()).To(Succeed())
		}()

		provider, err := NewProvider(context.Background(), m.Issuer(), in.skipIssuerVerification)
		if in.expectedError != "" {
			Expect(err).To(MatchError(HavePrefix(in.expectedError)))
			return
		}
		Expect(err).ToNot(HaveOccurred())

		endpoints := provider.Endpoints()
		Expect(endpoints.AuthURL).To(Equal(m.AuthorizationEndpoint()))
		Expect(endpoints.TokenURL).To(Equal(m.TokenEndpoint()))
		Expect(endpoints.JWKsURL).To(Equal(m.JWKSEndpoint()))
		Expect(endpoints.UserInfoURL).To(Equal(m.UserinfoEndpoint()))
	},
		Entry("with issuer verification and the issuer matches", &newProviderTableInput{
			skipIssuerVerification: false,
		}),
		Entry("with skip issuer verification and the issuer matches", &newProviderTableInput{
			skipIssuerVerification: true,
		}),
		Entry("with issuer verification and an invalid issuer", &newProviderTableInput{
			skipIssuerVerification: false,
			middlewares: func(m *mockoidc.MockOIDC) []func(http.Handler) http.Handler {
				return []func(http.Handler) http.Handler{
					newInvalidIssuerMiddleware(m),
				}
			},
			expectedError: "oidc: issuer did not match the issuer returned by provider",
		}),
		Entry("with skip issuer verification and an invalid issuer", &newProviderTableInput{
			skipIssuerVerification: true,
			middlewares: func(m *mockoidc.MockOIDC) []func(http.Handler) http.Handler {
				return []func(http.Handler) http.Handler{
					newInvalidIssuerMiddleware(m),
				}
			},
		}),
		Entry("when the issuer returns a bad response", &newProviderTableInput{
			skipIssuerVerification: false,
			middlewares: func(m *mockoidc.MockOIDC) []func(http.Handler) http.Handler {
				return []func(http.Handler) http.Handler{
					newBadRequestMiddleware(),
				}
			},
			expectedError: "failed to discover OIDC configuration: unexpected status \"400\"",
		}),
	)
})

func newInvalidIssuerMiddleware(m *mockoidc.MockOIDC) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			p := providerJSON{
				Issuer:      "invalid",
				AuthURL:     m.AuthorizationEndpoint(),
				TokenURL:    m.TokenEndpoint(),
				JWKsURL:     m.JWKSEndpoint(),
				UserInfoURL: m.UserinfoEndpoint(),
			}
			data, err := json.Marshal(p)
			if err != nil {
				rw.WriteHeader(500)
			}
			rw.Write(data)
		})
	}
}

func newBadRequestMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.WriteHeader(400)
		})
	}
}
