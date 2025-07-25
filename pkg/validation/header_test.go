package validation

import (
	"encoding/base64"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Headers", func() {
	type validateHeaderTableInput struct {
		headers      []options.Header
		expectedMsgs []string
	}

	validHeader1 := options.Header{
		Name: "X-Email",
		Values: []options.HeaderValue{
			{
				ClaimSource: &options.ClaimSource{
					Claim: "email",
				},
			},
		},
	}

	validHeader2 := options.Header{
		Name: "X-Forwarded-Auth",
		Values: []options.HeaderValue{
			{
				SecretSource: &options.SecretSource{
					Value: []byte(base64.StdEncoding.EncodeToString([]byte("secret"))),
				},
			},
		},
	}

	validHeader3 := options.Header{
		Name: "Authorization",
		Values: []options.HeaderValue{
			{
				ClaimSource: &options.ClaimSource{
					Claim: "email",
					BasicAuthPassword: &options.SecretSource{
						Value: []byte(base64.StdEncoding.EncodeToString([]byte("secret"))),
					},
				},
			},
		},
	}

	DescribeTable("validateHeaders",
		func(in validateHeaderTableInput) {
			Expect(validateHeaders(in.headers)).To(ConsistOf(in.expectedMsgs))
		},
		Entry("with no headers", validateHeaderTableInput{
			headers:      []options.Header{},
			expectedMsgs: []string{},
		}),
		Entry("with valid headers", validateHeaderTableInput{
			headers: []options.Header{
				validHeader1,
				validHeader2,
				validHeader3,
			},
			expectedMsgs: []string{},
		}),
		Entry("with multiple headers with the same name", validateHeaderTableInput{
			headers: []options.Header{
				validHeader1,
				validHeader1,
				validHeader2,
				validHeader2,
			},
			expectedMsgs: []string{
				"multiple headers found with name \"X-Email\": header names must be unique",
				"multiple headers found with name \"X-Forwarded-Auth\": header names must be unique",
			},
		}),
		Entry("with an unamed header", validateHeaderTableInput{
			headers: []options.Header{
				{},
				validHeader2,
			},
			expectedMsgs: []string{
				"header has empty name: names are required for all headers",
			},
		}),
		Entry("with a header which has a claim and secret source", validateHeaderTableInput{
			headers: []options.Header{
				{
					Name: "With-Claim-And-Secret",
					Values: []options.HeaderValue{
						{
							ClaimSource:  &options.ClaimSource{},
							SecretSource: &options.SecretSource{},
						},
					},
				},
				validHeader1,
			},
			expectedMsgs: []string{
				"invalid header \"With-Claim-And-Secret\": invalid values: header value has multiple entries: only one entry per value is allowed",
			},
		}),
		Entry("with a header which has a claim without a claim", validateHeaderTableInput{
			headers: []options.Header{
				{
					Name: "Without-Claim",
					Values: []options.HeaderValue{
						{
							ClaimSource: &options.ClaimSource{
								Prefix: "prefix",
							},
						},
					},
				},
				validHeader3,
			},
			expectedMsgs: []string{
				"invalid header \"Without-Claim\": invalid values: claim should not be empty",
			},
		}),
		Entry("with a header with invalid secret source", validateHeaderTableInput{
			headers: []options.Header{
				{
					Name: "With-Invalid-Secret",
					Values: []options.HeaderValue{
						{
							SecretSource: &options.SecretSource{},
						},
					},
				},
				validHeader1,
			},
			expectedMsgs: []string{
				"invalid header \"With-Invalid-Secret\": invalid values: multiple values specified for secret source: specify either value, fromEnv of fromFile",
			},
		}),
		Entry("with a header with invalid basicAuthPassword source", validateHeaderTableInput{
			headers: []options.Header{
				{
					Name: "With-Invalid-Basic-Auth",
					Values: []options.HeaderValue{
						{
							ClaimSource: &options.ClaimSource{
								Claim: "user",
								BasicAuthPassword: &options.SecretSource{
									FromEnv: "UNKNOWN_ENV",
								},
							},
						},
					},
				},
				validHeader1,
			},
			expectedMsgs: []string{
				"invalid header \"With-Invalid-Basic-Auth\": invalid values: invalid basicAuthPassword: error loading secret from environent: no value for for key \"UNKNOWN_ENV\"",
			},
		}),
	)
})
