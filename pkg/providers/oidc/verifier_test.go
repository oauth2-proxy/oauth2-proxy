package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Verify", func() {
	ctx := context.Background()

	It("Succeeds with default aud behavior", func() {
		result, err := verify(ctx, IDTokenVerificationOptions{
			AudienceClaims: []string{"aud"},
			ClientID:       "1226737",
			ExtraAudiences: []string{},
		}, payload{
			Iss: "https://foo",
			Aud: "1226737",
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Issuer).To(Equal("https://foo"))
		Expect(result.Audience).To(Equal([]string{"1226737"}))
	})

	It("Fails with default aud behavior", func() {
		result, err := verify(ctx, IDTokenVerificationOptions{
			AudienceClaims: []string{"aud"},
			ClientID:       "7817818",
			ExtraAudiences: []string{},
		}, payload{
			Iss: "https://foo",
			Aud: "1226737",
		})
		Expect(err).To(MatchError("audience from claim aud with value [1226737] does not match with " +
			"any of allowed audiences map[7817818:{}]"))
		Expect(result).To(BeNil())
	})

	It("Succeeds with extra audiences", func() {
		result, err := verify(ctx, IDTokenVerificationOptions{
			AudienceClaims: []string{"aud"},
			ClientID:       "7817818",
			ExtraAudiences: []string{"xyz", "1226737"},
		}, payload{
			Iss: "https://foo",
			Aud: "1226737",
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Issuer).To(Equal("https://foo"))
		Expect(result.Audience).To(Equal([]string{"1226737"}))
	})

	It("Fails with extra audiences", func() {
		result, err := verify(ctx, IDTokenVerificationOptions{
			AudienceClaims: []string{"aud"},
			ClientID:       "7817818",
			ExtraAudiences: []string{"xyz", "abc"},
		}, payload{
			Iss: "https://foo",
			Aud: "1226737",
		})

		Expect(err).To(MatchError("audience from claim aud with value [1226737] does not match with any " +
			"of allowed audiences map[7817818:{} abc:{} xyz:{}]"))
		Expect(result).To(BeNil())
	})

	It("Succeeds with non default aud behavior", func() {
		result, err := verify(ctx, IDTokenVerificationOptions{
			AudienceClaims: []string{"client_id"},
			ClientID:       "1226737",
			ExtraAudiences: []string{},
		}, payload{
			Iss:      "https://foo",
			ClientID: "1226737",
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Issuer).To(Equal("https://foo"))
		Expect(result.Audience).To(Equal([]string{"1226737"}))
	})

	It("Fails with non default aud behavior", func() {
		result, err := verify(ctx, IDTokenVerificationOptions{
			AudienceClaims: []string{"client_id"},
			ClientID:       "7817818",
			ExtraAudiences: []string{},
		}, payload{
			Iss:      "https://foo",
			ClientID: "1226737",
		})
		Expect(err).To(MatchError("audience from claim client_id with value [1226737] does not match with " +
			"any of allowed audiences map[7817818:{}]"))
		Expect(result).To(BeNil())
	})

	It("Succeeds with non default aud behavior and extra audiences", func() {
		result, err := verify(ctx, IDTokenVerificationOptions{
			AudienceClaims: []string{"client_id"},
			ClientID:       "7817818",
			ExtraAudiences: []string{"xyz", "1226737"},
		}, payload{
			Iss:      "https://foo",
			ClientID: "1226737",
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Issuer).To(Equal("https://foo"))
		Expect(result.Audience).To(Equal([]string{"1226737"}))
	})

	It("Fails with non default aud behavior and extra audiences", func() {
		result, err := verify(ctx, IDTokenVerificationOptions{
			AudienceClaims: []string{"client_id"},
			ClientID:       "7817818",
			ExtraAudiences: []string{"xyz", "abc"},
		}, payload{
			Iss:      "https://foo",
			ClientID: "1226737",
		})

		Expect(err).To(MatchError("audience from claim client_id with value [1226737] does not match with any " +
			"of allowed audiences map[7817818:{} abc:{} xyz:{}]"))
		Expect(result).To(BeNil())
	})

	It("Fails if audience claim does not exist", func() {
		result, err := verify(ctx, IDTokenVerificationOptions{
			AudienceClaims: []string{"not_exists"},
			ClientID:       "7817818",
			ExtraAudiences: []string{"xyz", "abc"},
		}, payload{
			Iss:      "https://foo",
			ClientID: "1226737",
			Aud:      "1226737",
		})

		Expect(err).To(MatchError("audience claims [not_exists] do not exist in claims: " +
			"map[aud:1226737 client_id:1226737 iss:https://foo]"))
		Expect(result).To(BeNil())
	})

	It("Succeeds with multiple audiences", func() {
		var result, err = verify(ctx, IDTokenVerificationOptions{
			AudienceClaims: []string{"client_id", "aud"},
			ClientID:       "123456789",
			ExtraAudiences: []string{"1226737"},
		}, payload{
			Iss:      "https://foo",
			ClientID: "123456789",
			Aud:      []string{"1226737", "123456789"},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Issuer).To(Equal("https://foo"))
		Expect(result.Audience).To(Equal([]string{"123456789"}))
	})

	It("Succeeds if aud claim match", func() {
		result, err := verify(ctx, IDTokenVerificationOptions{
			AudienceClaims: []string{"client_id", "aud"},
			ClientID:       "1226737",
			ExtraAudiences: []string{"xyz", "abc"},
		}, payload{
			Iss:      "https://foo",
			ClientID: "1226737",
			Aud:      "1226737",
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Issuer).To(Equal("https://foo"))
		Expect(result.Audience).To(Equal([]string{"1226737"}))
	})
})

var _ = Describe("VerifyLogout", func() {
	ctx := context.Background()
	defaultOptions := IDTokenVerificationOptions{
		AudienceClaims: []string{"aud"},
		ClientID:       "1226737",
		ExtraAudiences: []string{},
	}

	validLogoutPayload := func() logoutPayload {
		return logoutPayload{
			Iss:    "https://foo",
			Aud:    "1226737",
			Sub:    "user-123",
			Sid:    "sid-123",
			Jti:    "jti-123",
			Iat:    1700000000,
			Exp:    4102444800,
			Events: map[string]interface{}{backChannelLogoutEvent: map[string]interface{}{}},
		}
	}

	It("Succeeds with a valid logout token", func() {
		result, err := verifyLogout(ctx, defaultOptions, validLogoutPayload())

		Expect(err).ToNot(HaveOccurred())
		Expect(result.SessionID).To(Equal("sid-123"))
		Expect(result.Subject).To(Equal("user-123"))
		Expect(result.TokenID).To(Equal("jti-123"))
	})

	It("Succeeds with only a sub claim", func() {
		p := validLogoutPayload()
		p.Sid = ""

		result, err := verifyLogout(ctx, defaultOptions, p)

		Expect(err).ToNot(HaveOccurred())
		Expect(result.SessionID).To(BeEmpty())
		Expect(result.Subject).To(Equal("user-123"))
	})

	It("Fails when the audience does not match", func() {
		p := validLogoutPayload()
		p.Aud = "another-client"

		result, err := verifyLogout(ctx, defaultOptions, p)

		Expect(err).To(MatchError("audience from claim aud with value [another-client] does not match with " +
			"any of allowed audiences map[1226737:{}]"))
		Expect(result).To(BeNil())
	})

	It("Succeeds with extra audiences", func() {
		p := validLogoutPayload()
		p.Aud = "xyz"

		result, err := verifyLogout(ctx, IDTokenVerificationOptions{
			AudienceClaims: []string{"aud"},
			ClientID:       "1226737",
			ExtraAudiences: []string{"xyz"},
		}, p)

		Expect(err).ToNot(HaveOccurred())
		Expect(result.SessionID).To(Equal("sid-123"))
	})

	DescribeTable("Fails with an invalid logout token",
		func(mutate func(*logoutPayload), expectedErr string) {
			p := validLogoutPayload()
			mutate(&p)

			result, err := verifyLogout(ctx, defaultOptions, p)

			Expect(err).To(MatchError(ContainSubstring(expectedErr)))
			Expect(result).To(BeNil())
		},
		Entry("without the back-channel logout event", func(p *logoutPayload) { p.Events = nil },
			"missing required http://schemas.openid.net/event/backchannel-logout event"),
		Entry("with a nonce", func(p *logoutPayload) { p.Nonce = "n-123" }, "must not contain a 'nonce' claim"),
		Entry("without jti", func(p *logoutPayload) { p.Jti = "" }, "missing required claim 'jti'"),
		Entry("without exp", func(p *logoutPayload) { p.Exp = 0 }, "must contain an 'exp' claim"),
		Entry("without sub and sid", func(p *logoutPayload) { p.Sub, p.Sid = "", "" },
			"must contain a 'sub' claim, a 'sid' claim, or both"),
	)
})

const backChannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

type logoutPayload struct {
	Iss    string                 `json:"iss,omitempty"`
	Aud    interface{}            `json:"aud,omitempty"`
	Sub    string                 `json:"sub,omitempty"`
	Sid    string                 `json:"sid,omitempty"`
	Jti    string                 `json:"jti,omitempty"`
	Nonce  string                 `json:"nonce,omitempty"`
	Iat    int64                  `json:"iat,omitempty"`
	Exp    int64                  `json:"exp,omitempty"`
	Events map[string]interface{} `json:"events,omitempty"`
}

type payload struct {
	Iss      string      `json:"iss,omitempty"`
	Aud      interface{} `json:"aud,omitempty"`
	ClientID string      `json:"client_id,omitempty"`
}

type jwtToken struct {
	PrivateKey jose.JSONWebKey
	PublicKey  jose.JSONWebKey
	Token      string
}

type testVerifier struct {
	jwk jose.JSONWebKey
}

func (t *testVerifier) VerifySignature(_ context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, fmt.Errorf("oidc: malformed jwt: %v", err)
	}
	return jws.Verify(&t.jwk)
}

func verify(ctx context.Context, verificationOptions IDTokenVerificationOptions, payload payload) (*oidc.IDToken, error) {
	config := &oidc.Config{
		ClientID:          "1226737",
		SkipClientIDCheck: true,
		SkipExpiryCheck:   true, // required to not run in expired Token error during testing
	}
	rawToken, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	token, _ := createToken(rawToken)
	verifier := NewVerifier(oidc.NewVerifier("https://foo", &testVerifier{jwk: token.PublicKey}, config), verificationOptions)
	return verifier.Verify(ctx, token.Token)
}

func verifyLogout(ctx context.Context, verificationOptions IDTokenVerificationOptions, payload logoutPayload) (*oidc.LogoutToken, error) {
	config := &oidc.Config{
		ClientID:          "1226737",
		SkipClientIDCheck: true, // as in production: the audience is checked by our verifier
		SkipExpiryCheck:   true,
	}
	rawToken, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	token, _ := createToken(rawToken)
	verifier := NewVerifier(oidc.NewVerifier("https://foo", &testVerifier{jwk: token.PublicKey}, config), verificationOptions)
	return verifier.(LogoutTokenVerifier).VerifyLogout(ctx, token.Token)
}

func createToken(payload []byte) (*jwtToken, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1028)
	if err != nil {
		return nil, err
	}
	privateWebKey := jose.JSONWebKey{Key: privateKey, Algorithm: string(jose.RS256), KeyID: ""}
	publicWebKey := jose.JSONWebKey{Key: privateKey.Public(), Use: "sig", Algorithm: string(jose.RS256), KeyID: ""}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateWebKey}, nil)
	if err != nil {
		return nil, err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return nil, err
	}
	data, err := jws.CompactSerialize()
	if err != nil {
		return nil, err
	}
	return &jwtToken{
		PrivateKey: privateWebKey,
		PublicKey:  publicWebKey,
		Token:      data,
	}, nil
}
