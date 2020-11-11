package options

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Header", func() {
	type isZeroTableInput struct {
		source       ClaimSource
		expectIsZero bool
	}

	DescribeTable("ClaimSource.IsZero",
		func(in isZeroTableInput) {
			Expect(in.source.IsZero()).To(Equal(in.expectIsZero))
		},
		Entry("with no entries", isZeroTableInput{
			source:       ClaimSource{},
			expectIsZero: true,
		}),
		Entry("with a claim", isZeroTableInput{
			source: ClaimSource{
				Claim: "claim",
			},
			expectIsZero: false,
		}),
		Entry("with a prefix", isZeroTableInput{
			source: ClaimSource{
				Prefix: "prefix",
			},
			expectIsZero: false,
		}),
		Entry("with a BasicAuthPassword", isZeroTableInput{
			source: ClaimSource{
				BasicAuthPassword: SecretSource{
					FromEnv: "secret",
				},
			},
			expectIsZero: false,
		}),
		Entry("with an empty BasicAuthPassword", isZeroTableInput{
			source: ClaimSource{
				BasicAuthPassword: SecretSource{},
			},
			expectIsZero: true,
		}),
	)
})
