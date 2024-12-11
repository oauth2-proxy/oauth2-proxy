package middleware

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Session utilities suite", func() {
	Context("splitAuthHeader", func() {
		type splitAuthTableInput struct {
			header             string
			expectedErr        error
			expectedTokenType  string
			expectedTokenValue string
		}

		DescribeTable("with a header value",
			func(in splitAuthTableInput) {
				tt, tv, err := splitAuthHeader(in.header)
				if in.expectedErr != nil {
					Expect(err).To(MatchError(in.expectedErr))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(tt).To(Equal(in.expectedTokenType))
				Expect(tv).To(Equal(in.expectedTokenValue))
			},
			Entry("Bearer abcdef", splitAuthTableInput{
				header:             "Bearer abcdef",
				expectedErr:        nil,
				expectedTokenType:  "Bearer",
				expectedTokenValue: "abcdef",
			}),
			Entry("Bearer", splitAuthTableInput{
				header:             "Bearer",
				expectedErr:        errors.New("invalid authorization header: \"Bearer\""),
				expectedTokenType:  "",
				expectedTokenValue: "",
			}),
			Entry("Bearer abc def", splitAuthTableInput{
				header:             "Bearer abc def",
				expectedErr:        errors.New("invalid authorization header: \"Bearer abc def\""),
				expectedTokenType:  "",
				expectedTokenValue: "",
			}),
		)
	})

	Context("getBasicAuthCredentials", func() {
		type getBasicAuthCredentialsTableInput struct {
			token            string
			expectedErr      error
			expectedUser     string
			expectedPassword string
		}

		DescribeTable("from token",
			func(in getBasicAuthCredentialsTableInput) {
				user, password, err := getBasicAuthCredentials(in.token)
				if in.expectedErr != nil {
					Expect(err).To(MatchError(in.expectedErr))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(user).To(Equal(in.expectedUser))
				Expect(password).To(Equal(in.expectedPassword))
			},
			Entry("<no value>", getBasicAuthCredentialsTableInput{
				token:            "",
				expectedErr:      errors.New("invalid format: \"\""),
				expectedUser:     "",
				expectedPassword: "",
			}),
			Entry("invalid-base64", getBasicAuthCredentialsTableInput{
				token:            "invalid-base64",
				expectedErr:      errors.New("invalid basic auth token: illegal base64 data at input byte 7"),
				expectedUser:     "",
				expectedPassword: "",
			}),
			Entry("Base64(some-user:some-password)", getBasicAuthCredentialsTableInput{
				token:            "c29tZS11c2VyOnNvbWUtcGFzc3dvcmQ=",
				expectedErr:      nil,
				expectedUser:     "some-user",
				expectedPassword: "some-password",
			}),
			Entry("Base64(no-password:)", getBasicAuthCredentialsTableInput{
				token:            "bm8tcGFzc3dvcmQ6",
				expectedErr:      nil,
				expectedUser:     "no-password",
				expectedPassword: "",
			}),
			Entry("Base64(:no-user)", getBasicAuthCredentialsTableInput{
				token:            "Om5vLXVzZXI=",
				expectedErr:      nil,
				expectedUser:     "",
				expectedPassword: "no-user",
			}),
		)
	})
})
