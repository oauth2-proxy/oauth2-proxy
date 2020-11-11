package options

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Common", func() {
	type isZeroTableInput struct {
		source       SecretSource
		expectIsZero bool
	}

	DescribeTable("SecretSource.IsZero",
		func(in isZeroTableInput) {
			Expect(in.source.IsZero()).To(Equal(in.expectIsZero))
		},
		Entry("with no entries", isZeroTableInput{
			source:       SecretSource{},
			expectIsZero: true,
		}),
		Entry("with a value", isZeroTableInput{
			source: SecretSource{
				Value: []byte("secret"),
			},
			expectIsZero: false,
		}),
		Entry("with a fromEnv", isZeroTableInput{
			source: SecretSource{
				FromEnv: "secret",
			},
			expectIsZero: false,
		}),
		Entry("with a fromFile", isZeroTableInput{
			source: SecretSource{
				FromEnv: "secret",
			},
			expectIsZero: false,
		}),
	)
})
