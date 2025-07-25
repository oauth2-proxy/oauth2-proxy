package header

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Injector Suite", func() {
	Context("NewInjector", func() {
		type newInjectorTableInput struct {
			headers         []options.Header
			initialHeaders  http.Header
			session         *sessionsapi.SessionState
			expectedHeaders http.Header
			expectedErr     error
		}

		DescribeTable("creates an injector",
			func(in newInjectorTableInput) {
				injector, err := NewInjector(in.headers)
				if in.expectedErr != nil {
					Expect(err).To(MatchError(in.expectedErr))
					Expect(injector).To(BeNil())
					return
				}

				Expect(err).ToNot(HaveOccurred())
				Expect(injector).ToNot(BeNil())

				headers := in.initialHeaders.Clone()
				injector.Inject(headers, in.session)
				Expect(headers).To(Equal(in.expectedHeaders))
			},
			Entry("with no configured headers", newInjectorTableInput{
				headers: []options.Header{},
				initialHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				session: &sessionsapi.SessionState{},
				expectedHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				expectedErr: nil,
			}),
			Entry("with a static valued header from string", newInjectorTableInput{
				headers: []options.Header{
					{
						Name: "Secret",
						Values: []options.HeaderValue{
							{
								SecretSource: &options.SecretSource{
									Value: []byte("super-secret"),
								},
							},
						},
					},
				},
				initialHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				session: &sessionsapi.SessionState{},
				expectedHeaders: http.Header{
					"foo":    []string{"bar", "baz"},
					"Secret": []string{"super-secret"},
				},
				expectedErr: nil,
			}),
			Entry("with a static valued header from env", newInjectorTableInput{
				headers: []options.Header{
					{
						Name: "Secret",
						Values: []options.HeaderValue{
							{
								SecretSource: &options.SecretSource{
									FromEnv: "SECRET_ENV",
								},
							},
						},
					},
				},
				initialHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				session: &sessionsapi.SessionState{},
				expectedHeaders: http.Header{
					"foo":    []string{"bar", "baz"},
					"Secret": []string{"super-secret-env"},
				},
				expectedErr: nil,
			}),
			Entry("with a claim valued header", newInjectorTableInput{
				headers: []options.Header{
					{
						Name: "Claim",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim: "id_token",
								},
							},
						},
					},
				},
				initialHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				session: &sessionsapi.SessionState{
					IDToken: "IDToken-1234",
				},
				expectedHeaders: http.Header{
					"foo":   []string{"bar", "baz"},
					"Claim": []string{"IDToken-1234"},
				},
				expectedErr: nil,
			}),
			Entry("with a claim valued header and a nil session", newInjectorTableInput{
				headers: []options.Header{
					{
						Name: "Claim",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim: "id_token",
								},
							},
						},
					},
				},
				initialHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				session: nil,
				expectedHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				expectedErr: nil,
			}),
			Entry("with a prefixed claim valued header", newInjectorTableInput{
				headers: []options.Header{
					{
						Name: "Claim",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim:  "id_token",
									Prefix: "Bearer ",
								},
							},
						},
					},
				},
				initialHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				session: &sessionsapi.SessionState{
					IDToken: "IDToken-1234",
				},
				expectedHeaders: http.Header{
					"foo":   []string{"bar", "baz"},
					"Claim": []string{"Bearer IDToken-1234"},
				},
				expectedErr: nil,
			}),
			Entry("with a prefixed claim valued header missing the claim", newInjectorTableInput{
				headers: []options.Header{
					{
						Name: "Claim",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim:  "idToken",
									Prefix: "Bearer ",
								},
							},
						},
					},
				},
				initialHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				session: &sessionsapi.SessionState{},
				expectedHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				expectedErr: nil,
			}),
			Entry("with a basicAuthPassword and claim valued header", newInjectorTableInput{
				headers: []options.Header{
					{
						Name: "X-Auth-Request-Authorization",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim: "user",
									BasicAuthPassword: &options.SecretSource{
										Value: []byte("basic-password"),
									},
								},
							},
						},
					},
				},
				initialHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				session: &sessionsapi.SessionState{
					User: "user-123",
				},
				expectedHeaders: http.Header{
					"foo":                          []string{"bar", "baz"},
					"X-Auth-Request-Authorization": []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("user-123:basic-password"))},
				},
				expectedErr: nil,
			}),
			Entry("with a basicAuthPassword and claim valued header missing the claim", newInjectorTableInput{
				headers: []options.Header{
					{
						Name: "X-Auth-Request-Authorization",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim: "user",
									BasicAuthPassword: &options.SecretSource{
										Value: []byte(base64.StdEncoding.EncodeToString([]byte("basic-password"))),
									},
								},
							},
						},
					},
				},
				initialHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				session: &sessionsapi.SessionState{},
				expectedHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				expectedErr: nil,
			}),
			Entry("with a header that already exists", newInjectorTableInput{
				headers: []options.Header{
					{
						Name: "X-Auth-Request-User",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim: "user",
								},
							},
						},
					},
				},
				initialHeaders: http.Header{
					"X-Auth-Request-User": []string{"user"},
				},
				session: &sessionsapi.SessionState{
					User: "user-123",
				},
				expectedHeaders: http.Header{
					"X-Auth-Request-User": []string{"user", "user-123"},
				},
				expectedErr: nil,
			}),
			Entry("with a claim and secret valued header value", newInjectorTableInput{
				headers: []options.Header{
					{
						Name: "Claim",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim: "id_token",
								},
								SecretSource: &options.SecretSource{
									FromEnv: "SECRET_ENV",
								},
							},
						},
					},
				},
				initialHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				session: &sessionsapi.SessionState{
					IDToken: "IDToken-1234",
				},
				expectedHeaders: nil,
				expectedErr:     errors.New("error building injector for header \"Claim\": header \"Claim\" value has multiple entries: only one entry per value is allowed"),
			}),
			Entry("with an invalid static valued header", newInjectorTableInput{
				headers: []options.Header{
					{
						Name: "Secret",
						Values: []options.HeaderValue{
							{
								SecretSource: &options.SecretSource{
									FromEnv:  "SECRET_ENV",
									FromFile: "secret-file",
								},
							},
						},
					},
				},
				initialHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				session:         &sessionsapi.SessionState{},
				expectedHeaders: nil,
				expectedErr:     errors.New("error building injector for header \"Secret\": error getting secret value: secret source is invalid: exactly one entry required, specify either value, fromEnv or fromFile"),
			}),
			Entry("with an invalid basicAuthPassword claim valued header", newInjectorTableInput{
				headers: []options.Header{
					{
						Name: "X-Auth-Request-Authorization",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim: "user",
									BasicAuthPassword: &options.SecretSource{
										Value:   []byte(base64.StdEncoding.EncodeToString([]byte("basic-password"))),
										FromEnv: "SECRET_ENV",
									},
								},
							},
						},
					},
				},
				initialHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				session: &sessionsapi.SessionState{
					User: "user-123",
				},
				expectedHeaders: nil,
				expectedErr:     errors.New("error building injector for header \"X-Auth-Request-Authorization\": error loading basicAuthPassword: secret source is invalid: exactly one entry required, specify either value, fromEnv or fromFile"),
			}),
			Entry("with a mix of configured headers", newInjectorTableInput{
				headers: []options.Header{
					{
						Name: "X-Auth-Request-Authorization",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim: "user",
									BasicAuthPassword: &options.SecretSource{
										Value: []byte("basic-password"),
									},
								},
							},
						},
					},
					{
						Name: "X-Auth-Request-User",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim: "user",
								},
							},
						},
					},
					{
						Name: "X-Auth-Request-Email",
						Values: []options.HeaderValue{
							{
								ClaimSource: &options.ClaimSource{
									Claim: "email",
								},
							},
						},
					},
					{
						Name: "X-Auth-Request-Version-Info",
						Values: []options.HeaderValue{
							{
								SecretSource: &options.SecretSource{
									Value: []byte("major=1"),
								},
							},
							{
								SecretSource: &options.SecretSource{
									Value: []byte("minor=2"),
								},
							},
							{
								SecretSource: &options.SecretSource{
									Value: []byte("patch=3"),
								},
							},
						},
					},
				},
				initialHeaders: http.Header{
					"foo": []string{"bar", "baz"},
				},
				session: &sessionsapi.SessionState{
					User:  "user-123",
					Email: "user@example.com",
				},
				expectedHeaders: http.Header{
					"foo":                          []string{"bar", "baz"},
					"X-Auth-Request-Authorization": []string{"Basic " + base64.StdEncoding.EncodeToString([]byte("user-123:basic-password"))},
					"X-Auth-Request-User":          []string{"user-123"},
					"X-Auth-Request-Email":         []string{"user@example.com"},
					"X-Auth-Request-Version-Info":  []string{"major=1", "minor=2", "patch=3"},
				},
				expectedErr: nil,
			}),
		)
	})
})
