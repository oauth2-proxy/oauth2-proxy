package options

import (
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("AlphaOptions", func() {
	Describe("collectHeaderClaimsIntoProviders", func() {
		It("adds non-builtin claims from injectRequestHeaders to provider AdditionalClaims", func() {
			opts := NewOptions()
			opts.Providers = Providers{
				{
					ID:   "test",
					Type: "oidc",
				},
			}
			opts.InjectRequestHeaders = []Header{
				{
					Name: "X-Forwarded-Upn",
					Values: []HeaderValue{
						{ClaimSource: &ClaimSource{Claim: "upn"}},
					},
				},
				{
					Name: "X-Forwarded-GivenName",
					Values: []HeaderValue{
						{ClaimSource: &ClaimSource{Claim: "given_name"}},
					},
				},
			}

			collectHeaderClaimsIntoProviders(opts)

			claims := opts.Providers[0].AdditionalClaims
			sort.Strings(claims)
			Expect(claims).To(ConsistOf("given_name", "upn"))
		})

		It("does not duplicate claims already in AdditionalClaims", func() {
			opts := NewOptions()
			opts.Providers = Providers{
				{
					ID:               "test",
					Type:             "oidc",
					AdditionalClaims: []string{"upn"},
				},
			}
			opts.InjectRequestHeaders = []Header{
				{
					Name: "X-Forwarded-Upn",
					Values: []HeaderValue{
						{ClaimSource: &ClaimSource{Claim: "upn"}},
					},
				},
			}

			collectHeaderClaimsIntoProviders(opts)

			Expect(opts.Providers[0].AdditionalClaims).To(Equal([]string{"upn"}))
		})

		It("skips builtin session claims", func() {
			opts := NewOptions()
			opts.Providers = Providers{
				{
					ID:   "test",
					Type: "oidc",
				},
			}
			opts.InjectRequestHeaders = []Header{
				{
					Name: "X-Email",
					Values: []HeaderValue{
						{ClaimSource: &ClaimSource{Claim: "email"}},
					},
				},
				{
					Name: "X-User",
					Values: []HeaderValue{
						{ClaimSource: &ClaimSource{Claim: "user"}},
					},
				},
				{
					Name: "X-Groups",
					Values: []HeaderValue{
						{ClaimSource: &ClaimSource{Claim: "groups"}},
					},
				},
				{
					Name: "X-Token",
					Values: []HeaderValue{
						{ClaimSource: &ClaimSource{Claim: "access_token"}},
					},
				},
			}

			collectHeaderClaimsIntoProviders(opts)

			Expect(opts.Providers[0].AdditionalClaims).To(BeEmpty())
		})

		It("also collects claims from injectResponseHeaders", func() {
			opts := NewOptions()
			opts.Providers = Providers{
				{
					ID:   "test",
					Type: "oidc",
				},
			}
			opts.InjectResponseHeaders = []Header{
				{
					Name: "X-Family-Name",
					Values: []HeaderValue{
						{ClaimSource: &ClaimSource{Claim: "family_name"}},
					},
				},
			}

			collectHeaderClaimsIntoProviders(opts)

			Expect(opts.Providers[0].AdditionalClaims).To(ConsistOf("family_name"))
		})

		It("adds claims to all providers", func() {
			opts := NewOptions()
			opts.Providers = Providers{
				{
					ID:   "provider1",
					Type: "oidc",
				},
				{
					ID:   "provider2",
					Type: "oidc",
				},
			}
			opts.InjectRequestHeaders = []Header{
				{
					Name: "X-Upn",
					Values: []HeaderValue{
						{ClaimSource: &ClaimSource{Claim: "upn"}},
					},
				},
			}

			collectHeaderClaimsIntoProviders(opts)

			Expect(opts.Providers[0].AdditionalClaims).To(ConsistOf("upn"))
			Expect(opts.Providers[1].AdditionalClaims).To(ConsistOf("upn"))
		})

		It("ignores headers with only SecretSource values", func() {
			opts := NewOptions()
			opts.Providers = Providers{
				{
					ID:   "test",
					Type: "oidc",
				},
			}
			opts.InjectRequestHeaders = []Header{
				{
					Name: "X-Static",
					Values: []HeaderValue{
						{SecretSource: &SecretSource{Value: []byte("static-value")}},
					},
				},
			}

			collectHeaderClaimsIntoProviders(opts)

			Expect(opts.Providers[0].AdditionalClaims).To(BeEmpty())
		})

		It("does nothing when no headers are configured", func() {
			opts := NewOptions()
			opts.Providers = Providers{
				{
					ID:   "test",
					Type: "oidc",
				},
			}

			collectHeaderClaimsIntoProviders(opts)

			Expect(opts.Providers[0].AdditionalClaims).To(BeNil())
		})
	})
})
