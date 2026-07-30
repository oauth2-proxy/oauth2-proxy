package oidc

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/mockoidc"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var tempDir string
var invalidPublicKeyFilePath string
var validPublicKeyFilePath string

var _ = BeforeSuite(func() {
	var err error

	// Create a temporary directory and public key file
	tempDir, err = os.MkdirTemp("/tmp", "provider-verifier-test")
	Expect(err).ToNot(HaveOccurred())

	invalidPublicKeyFilePath = filepath.Join(tempDir, "invalid.key")
	validPublicKeyFilePath = filepath.Join(tempDir, "valid.key")

	invalidKeyContents := []byte(`-----BEGIN INVALID KEY-----
ThisIsNotAValidKey
-----END INVALID KEY-----`)
	Expect(os.WriteFile(invalidPublicKeyFilePath, invalidKeyContents, 0644)).To(Succeed())

	validKeyContents := []byte(`-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALBJK+8qU+aQu2bHxJ8E95AIu2NINztM
NmX9R2zI9xlXN8wGQG8kWLYoRLbyiZwY9kdzOBGvYci64wHIjtFswHcCAwEAAQ==
-----END PUBLIC KEY-----`)
	Expect(os.WriteFile(validPublicKeyFilePath, validKeyContents, 0644)).To(Succeed())
})

var _ = AfterSuite(func() {
	// Clean up temporary directory
	Expect(os.RemoveAll(tempDir)).To(Succeed())
})

var _ = Describe("ProviderVerifier", func() {
	var m *mockoidc.MockOIDC

	BeforeEach(func() {
		var err error
		m, err = mockoidc.Run()
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		Expect(m.Shutdown()).To(Succeed())
	})

	type newProviderVerifierTableInput struct {
		modifyOpts    func(*ProviderVerifierOptions)
		expectedError string
	}

	DescribeTable("when constructing the provider verifier", func(in *newProviderVerifierTableInput) {
		opts := ProviderVerifierOptions{
			AudienceClaims: []string{"aud"},
			ClientID:       m.Config().ClientID,
			ExtraAudiences: []string{},
			IssuerURL:      m.Issuer(),
		}
		if in.modifyOpts != nil {
			in.modifyOpts(&opts)
		}

		pv, err := NewProviderVerifier(context.Background(), opts)
		if in.expectedError != "" {
			Expect(err).To(MatchError(HavePrefix(in.expectedError)))
			return
		}
		Expect(err).ToNot(HaveOccurred())

		Expect(pv.DiscoveryEnabled()).ToNot(Equal(opts.SkipDiscovery), "DiscoveryEnabled should be the reverse of skip discovery")
		Expect(pv.Provider()).ToNot(BeNil())

		if pv.DiscoveryEnabled() {
			endpoints := pv.Provider().Endpoints()
			Expect(endpoints.AuthURL).To(Equal(m.AuthorizationEndpoint()))
			Expect(endpoints.TokenURL).To(Equal(m.TokenEndpoint()))
			Expect(endpoints.JWKsURL).To(Equal(m.JWKSEndpoint()))
			Expect(endpoints.UserInfoURL).To(Equal(m.UserinfoEndpoint()))
		}
	},
		Entry("should be succesfful when discovering the OIDC provider", &newProviderVerifierTableInput{
			modifyOpts: func(_ *ProviderVerifierOptions) {},
		}),
		Entry("when the issuer URL is missing", &newProviderVerifierTableInput{
			modifyOpts: func(p *ProviderVerifierOptions) {
				p.IssuerURL = ""
			},
			expectedError: "invalid provider verifier options: missing required setting: issuer-url",
		}),
		Entry("when the issuer URL is invalid", &newProviderVerifierTableInput{
			modifyOpts: func(p *ProviderVerifierOptions) {
				p.IssuerURL = "invalid"
			},
			expectedError: "could not get verifier builder: error while discovery OIDC configuration: failed to discover OIDC configuration: error performing request: Get \"invalid/.well-known/openid-configuration\": unsupported protocol scheme \"\"",
		}),
		Entry("with skip discovery and the JWKs URL is missing", &newProviderVerifierTableInput{
			modifyOpts: func(p *ProviderVerifierOptions) {
				p.SkipDiscovery = true
				p.JWKsURL = ""
			},
			expectedError: "invalid provider verifier options: missing required setting: jwks-url or public-key-files",
		}),
		Entry("with skip discovery, the JWKs URL not empty and len(PublicKeyFiles) is greater than 0", &newProviderVerifierTableInput{
			modifyOpts: func(p *ProviderVerifierOptions) {
				p.SkipDiscovery = true
				p.JWKsURL = "notEmpty"
				p.PublicKeyFiles = []string{"notEmpty"}
			},
			expectedError: "invalid provider verifier options: mutually exclusive settings: jwks-url and public-key-files",
		}),
		Entry("should be successful when skipping discovery with the JWKs URL specified", &newProviderVerifierTableInput{
			modifyOpts: func(p *ProviderVerifierOptions) {
				p.SkipDiscovery = true
				p.JWKsURL = m.JWKSEndpoint()
			},
		}),
		Entry("should pass when the key is valid", &newProviderVerifierTableInput{
			modifyOpts: func(p *ProviderVerifierOptions) {
				p.SkipDiscovery = true
				p.PublicKeyFiles = []string{validPublicKeyFilePath}
			},
		}),
		Entry("should fail when the key is invalid", &newProviderVerifierTableInput{
			modifyOpts: func(p *ProviderVerifierOptions) {
				p.SkipDiscovery = true
				p.PublicKeyFiles = []string{invalidPublicKeyFilePath}
			},
			expectedError: "could not get verifier builder: error while parsing public keys",
		}),
		Entry("should fail when the key file is not found", &newProviderVerifierTableInput{
			modifyOpts: func(p *ProviderVerifierOptions) {
				p.SkipDiscovery = true
				p.PublicKeyFiles = []string{"non-existing"}
			},
			expectedError: "could not get verifier builder: error while parsing public keys: failed to read file",
		}),
	)

	type verifierTableInput struct {
		modifyOpts    func(*ProviderVerifierOptions)
		modifyClaims  func(claims *jwt.RegisteredClaims)
		expectedError string
	}

	DescribeTable("when constructing the provider verifier", func(in *verifierTableInput) {
		opts := ProviderVerifierOptions{
			AudienceClaims: []string{"aud"},
			ClientID:       m.Config().ClientID,
			ExtraAudiences: []string{},
			IssuerURL:      m.Issuer(),
		}
		if in.modifyOpts != nil {
			in.modifyOpts(&opts)
		}

		pv, err := NewProviderVerifier(context.Background(), opts)
		Expect(err).ToNot(HaveOccurred())

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{m.Config().ClientID},
			Issuer:    m.Issuer(),
			ExpiresAt: jwt.NewNumericDate(now.Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			Subject:   "user",
		}
		if in.modifyClaims != nil {
			in.modifyClaims(&claims)
		}

		rawIDToken, err := m.Keypair.SignJWT(claims)
		Expect(err).ToNot(HaveOccurred())

		idToken, err := pv.Verifier().Verify(context.Background(), rawIDToken)
		if in.expectedError != "" {
			Expect(err).To(MatchError(HavePrefix(in.expectedError)))
			return
		}
		Expect(err).ToNot(HaveOccurred())

		Expect(idToken.Issuer).To(Equal(claims.Issuer))
		Expect(idToken.Audience).To(ConsistOf(claims.Audience))
		Expect(idToken.Subject).To(Equal(claims.Subject))
	},
		Entry("with the default opts and claims", &verifierTableInput{}),
		Entry("with skip discovery and an allowed signing algorithm", &verifierTableInput{
			modifyOpts: func(p *ProviderVerifierOptions) {
				p.SkipDiscovery = true
				p.JWKsURL = m.JWKSEndpoint()
				p.SupportedSigningAlgs = []string{"RS256"}
			},
		}),
		Entry("with skip discovery and a disallowed signing algorithm", &verifierTableInput{
			modifyOpts: func(p *ProviderVerifierOptions) {
				p.SkipDiscovery = true
				p.JWKsURL = m.JWKSEndpoint()
				p.SupportedSigningAlgs = []string{"HS256"}
			},
			expectedError: "failed to verify token: oidc: malformed jwt: unexpected signature algorithm \"RS256\"; expected [\"HS256\"]",
		}),
		Entry("when the audience is mismatched", &verifierTableInput{
			modifyClaims: func(j *jwt.RegisteredClaims) {
				j.Audience = jwt.ClaimStrings{"OtherClient"}
			},
			expectedError: "audience from claim aud with value [OtherClient] does not match with any of allowed audiences",
		}),
		Entry("when the audience is an extra audience", &verifierTableInput{
			modifyOpts: func(p *ProviderVerifierOptions) {
				p.ExtraAudiences = []string{"ExtraIssuer"}
			},
			modifyClaims: func(j *jwt.RegisteredClaims) {
				j.Audience = jwt.ClaimStrings{"ExtraIssuer"}
			},
		}),
		Entry("when the issuer is mismatched", &verifierTableInput{
			modifyClaims: func(j *jwt.RegisteredClaims) {
				j.Issuer = "OtherIssuer"
			},
			expectedError: "failed to verify token: oidc: id token issued by a different provider",
		}),
		Entry("when the issuer is mismatched with skip issuer verification", &verifierTableInput{
			modifyOpts: func(p *ProviderVerifierOptions) {
				p.SkipIssuerVerification = true
			},
			modifyClaims: func(j *jwt.RegisteredClaims) {
				j.Issuer = "OtherIssuer"
			},
		}),
		Entry("when the token has expired", &verifierTableInput{
			modifyClaims: func(j *jwt.RegisteredClaims) {
				j.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-1 * time.Hour))
			},
			expectedError: "failed to verify token: oidc: token is expired",
		}),
	)

	Describe("intersectSigningAlgs", func() {
		DescribeTable("when determining allowed signing algorithms", func(discoveredSigningAlgs, configuredSigningAlgs, expected []string, expectedError string) {
			actual, err := intersectSigningAlgs(discoveredSigningAlgs, configuredSigningAlgs)
			Expect(actual).To(Equal(expected))
			if len(expectedError) > 0 {
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal(expectedError))
			}
		},
			Entry("returns discovered values when no configured values are provided", []string{"RS256", "HS256"}, []string(nil), []string{"RS256", "HS256"}, ""),
			Entry("returns configured values when no discovered values are provided", []string(nil), []string{"RS256"}, []string{"RS256"}, ""),
			Entry("returns the configured order of the intersection", []string{"RS256", "HS256", "EdDSA"}, []string{"EdDSA", "RS256"}, []string{"EdDSA", "RS256"}, ""),
			Entry("returns an error when there is no intersection", []string{"RS256", "HS256"}, []string{"EdDSA"}, nil, "no supported signing algorithms in common between provider and configuration: discovered=[RS256 HS256], configured=[EdDSA]"),
		)
	})

	It("uses the intersection between discovered and configured signing algorithms", func() {
		customServer, err := mockoidc.NewServer(nil)
		Expect(err).ToNot(HaveOccurred())
		customServer.AddMiddleware(newConfiguredSigningAlgsIssuerMiddleware(customServer, []string{"RS256", "HS256"}))

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())

		Expect(customServer.Start(listener, nil)).To(Succeed())
		defer func() {
			Expect(customServer.Shutdown()).To(Succeed())
		}()

		pv, err := NewProviderVerifier(context.Background(), ProviderVerifierOptions{
			AudienceClaims:       []string{"aud"},
			ClientID:             customServer.Config().ClientID,
			ExtraAudiences:       []string{},
			IssuerURL:            customServer.Issuer(),
			SupportedSigningAlgs: []string{"HS256"},
		})
		Expect(err).ToNot(HaveOccurred())

		rawIDToken, err := customServer.Keypair.SignJWT(jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{customServer.Config().ClientID},
			Issuer:    customServer.Issuer(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "user",
		})
		Expect(err).ToNot(HaveOccurred())

		_, err = pv.Verifier().Verify(context.Background(), rawIDToken)
		Expect(err).To(MatchError(HavePrefix("failed to verify token: oidc: malformed jwt: unexpected signature algorithm \"RS256\"; expected [\"HS256\"]")))
	})
})

func newConfiguredSigningAlgsIssuerMiddleware(m *mockoidc.MockOIDC, supportedSigningAlgs []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			provider := providerJSON{
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
