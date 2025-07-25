package middleware

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Headers Suite", func() {
	type headersTableInput struct {
		headers         []options.Header
		initialHeaders  http.Header
		session         *sessionsapi.SessionState
		expectedHeaders http.Header
		expectedErr     string
	}

	DescribeTable("the request header injector",
		func(in headersTableInput) {
			scope := &middlewareapi.RequestScope{
				Session: in.session,
			}

			// Set up the request with a request scope
			req := httptest.NewRequest("", "/", nil)
			req = middlewareapi.AddRequestScope(req, scope)
			req.Header = in.initialHeaders.Clone()

			rw := httptest.NewRecorder()

			// Create the handler with a next handler that will capture the headers
			// from the request
			var gotHeaders http.Header
			injector, err := NewRequestHeaderInjector(in.headers)
			if in.expectedErr != "" {
				Expect(err).To(MatchError(in.expectedErr))
				return
			}
			Expect(err).ToNot(HaveOccurred())

			handler := injector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHeaders = r.Header.Clone()
			}))
			handler.ServeHTTP(rw, req)

			Expect(gotHeaders).To(Equal(in.expectedHeaders))
		},
		Entry("with no configured headers", headersTableInput{
			headers: []options.Header{},
			initialHeaders: http.Header{
				"Foo": []string{"bar", "baz"},
			},
			session: &sessionsapi.SessionState{},
			expectedHeaders: http.Header{
				"Foo": []string{"bar,baz"},
			},
			expectedErr: "",
		}),
		Entry("with a claim valued header", headersTableInput{
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
				"Foo": []string{"bar", "baz"},
			},
			session: &sessionsapi.SessionState{
				IDToken: "IDToken-1234",
			},
			expectedHeaders: http.Header{
				"Foo":   []string{"bar,baz"},
				"Claim": []string{"IDToken-1234"},
			},
			expectedErr: "",
		}),
		Entry("with a claim valued header (without preservation)", headersTableInput{
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
				"Claim": []string{"bar", "baz"},
			},
			session: &sessionsapi.SessionState{
				IDToken: "IDToken-1234",
			},
			expectedHeaders: http.Header{
				"Claim": []string{"IDToken-1234"},
			},
			expectedErr: "",
		}),
		Entry("with a claim valued header (with preservation)", headersTableInput{
			headers: []options.Header{
				{
					Name:                 "Claim",
					PreserveRequestValue: true,
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
				"Claim": []string{"bar", "baz"},
			},
			session: &sessionsapi.SessionState{
				IDToken: "IDToken-1234",
			},
			expectedHeaders: http.Header{
				"Claim": []string{"bar,baz,IDToken-1234"},
			},
			expectedErr: "",
		}),
		Entry("with a claim valued header that's not present (without preservation)", headersTableInput{
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
				"Claim": []string{"bar", "baz"},
			},
			session:         nil,
			expectedHeaders: http.Header{},
			expectedErr:     "",
		}),
		Entry("with a claim valued header that's not present (with preservation)", headersTableInput{
			headers: []options.Header{
				{
					Name:                 "Claim",
					PreserveRequestValue: true,
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
				"Claim": []string{"bar", "baz"},
			},
			session: nil,
			expectedHeaders: http.Header{
				"Claim": []string{"bar,baz"},
			},
			expectedErr: "",
		}),
		Entry("with an invalid basicAuthPassword claim valued header", headersTableInput{
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
			expectedErr:     "error building request header injector: error building request injector: error building injector for header \"X-Auth-Request-Authorization\": error loading basicAuthPassword: secret source is invalid: exactly one entry required, specify either value, fromEnv or fromFile",
		}),
	)

	DescribeTable("the response header injector",
		func(in headersTableInput) {
			scope := &middlewareapi.RequestScope{
				Session: in.session,
			}

			// Set up the request with a request scope
			req := httptest.NewRequest("", "/", nil)
			req = middlewareapi.AddRequestScope(req, scope)

			rw := httptest.NewRecorder()
			for key, values := range in.initialHeaders {
				for _, value := range values {
					rw.Header().Add(key, value)
				}
			}

			// Create the handler with a next handler that will capture the headers
			// from the request
			var gotHeaders http.Header
			injector, err := NewResponseHeaderInjector(in.headers)
			if in.expectedErr != "" {
				Expect(err).To(MatchError(in.expectedErr))
				return
			}
			Expect(err).ToNot(HaveOccurred())

			handler := injector(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHeaders = w.Header().Clone()
			}))
			handler.ServeHTTP(rw, req)

			Expect(gotHeaders).To(Equal(in.expectedHeaders))
		},
		Entry("with no configured headers", headersTableInput{
			headers: []options.Header{},
			initialHeaders: http.Header{
				"Foo": []string{"bar", "baz"},
			},
			session: &sessionsapi.SessionState{},
			expectedHeaders: http.Header{
				"Foo": []string{"bar,baz"},
			},
			expectedErr: "",
		}),

		Entry("with flattenHeaders (set-cookie and any other)", headersTableInput{
			headers: []options.Header{
				{
					Name: "Set-Cookie",
					Values: []options.HeaderValue{
						{
							SecretSource: &options.SecretSource{
								Value: []byte("_oauth2_proxy=ey123123123"),
							},
						},
					},
				},
				{
					Name: "X-Auth-User",
					Values: []options.HeaderValue{
						{
							SecretSource: &options.SecretSource{
								Value: []byte("oauth_user"),
							},
						},
					},
				},
			},
			initialHeaders: http.Header{
				"Set-Cookie":  []string{"cookie1=value1", "cookie2=value2"},
				"X-Auth-User": []string{"oauth_user_1"},
			},

			expectedHeaders: http.Header{
				"Set-Cookie":  []string{"cookie1=value1", "cookie2=value2", "_oauth2_proxy=ey123123123"},
				"X-Auth-User": []string{"oauth_user_1,oauth_user"},
			},
			expectedErr: "",
		}),

		Entry("with a claim valued header", headersTableInput{
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
				"Foo": []string{"bar", "baz"},
			},
			session: &sessionsapi.SessionState{
				IDToken: "IDToken-1234",
			},
			expectedHeaders: http.Header{
				"Foo":   []string{"bar,baz"},
				"Claim": []string{"IDToken-1234"},
			},
			expectedErr: "",
		}),
		Entry("with a claim valued header (without preservation)", headersTableInput{
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
				"Claim": []string{"bar", "baz"},
			},
			session: &sessionsapi.SessionState{
				IDToken: "IDToken-1234",
			},
			expectedHeaders: http.Header{
				"Claim": []string{"bar,baz,IDToken-1234"},
			},
			expectedErr: "",
		}),
		Entry("with a claim valued header (with preservation)", headersTableInput{
			headers: []options.Header{
				{
					Name:                 "Claim",
					PreserveRequestValue: true,
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
				"Claim": []string{"bar", "baz"},
			},
			session: &sessionsapi.SessionState{
				IDToken: "IDToken-1234",
			},
			expectedHeaders: http.Header{
				"Claim": []string{"bar,baz,IDToken-1234"},
			},
			expectedErr: "",
		}),
		Entry("with a claim valued header that's not present (without preservation)", headersTableInput{
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
				"Claim": []string{"bar", "baz"},
			},
			session: nil,
			expectedHeaders: http.Header{
				"Claim": []string{"bar,baz"},
			},
			expectedErr: "",
		}),
		Entry("with a claim valued header that's not present (with preservation)", headersTableInput{
			headers: []options.Header{
				{
					Name:                 "Claim",
					PreserveRequestValue: true,
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
				"Claim": []string{"bar", "baz"},
			},
			session: nil,
			expectedHeaders: http.Header{
				"Claim": []string{"bar,baz"},
			},
			expectedErr: "",
		}),
		Entry("with an invalid basicAuthPassword claim valued header", headersTableInput{
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
			expectedErr:     "error building response header injector: error building response injector: error building injector for header \"X-Auth-Request-Authorization\": error loading basicAuthPassword: secret source is invalid: exactly one entry required, specify either value, fromEnv or fromFile",
		}),
	)
})
