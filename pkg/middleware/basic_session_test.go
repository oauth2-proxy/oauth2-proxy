package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	adminUser     = "admin"
	adminPassword = "Adm1n1str$t0r"
	user1         = "user1"
	user1Password = "UsErOn3P455"
	user2         = "user2"
	user2Password = "us3r2P455W0Rd!"
)

var _ = Describe("Basic Auth Session Suite", func() {
	Context("BasicAuthSessionLoader", func() {

		type basicAuthSessionLoaderTableInput struct {
			authorizationHeader string
			preferEmail         bool
			sessionGroups       []string
			existingSession     *sessionsapi.SessionState
			expectedSession     *sessionsapi.SessionState
		}

		DescribeTable("with an authorization header",
			func(in basicAuthSessionLoaderTableInput) {
				scope := &middlewareapi.RequestScope{
					Session: in.existingSession,
				}

				// Set up the request with the authorization header and a request scope
				req := httptest.NewRequest("", "/", nil)
				req.Header.Set("Authorization", in.authorizationHeader)
				req = middlewareapi.AddRequestScope(req, scope)

				rw := httptest.NewRecorder()

				validator := fakeBasicValidator{
					users: map[string]string{
						adminUser: adminPassword,
						user1:     user1Password,
						user2:     user2Password,
					},
				}

				// Create the handler with a next handler that will capture the session
				// from the scope
				var gotSession *sessionsapi.SessionState
				handler := NewBasicAuthSessionLoader(validator, in.sessionGroups, in.preferEmail)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					gotSession = middlewareapi.GetRequestScope(r).Session
				}))
				handler.ServeHTTP(rw, req)

				Expect(gotSession).To(Equal(in.expectedSession))
			},
			Entry("<no value>", basicAuthSessionLoaderTableInput{
				authorizationHeader: "",
				existingSession:     nil,
				expectedSession:     nil,
			}),
			Entry("abcdef", basicAuthSessionLoaderTableInput{
				authorizationHeader: "abcdef",
				existingSession:     nil,
				expectedSession:     nil,
			}),
			Entry("abcdef (with existing session)", basicAuthSessionLoaderTableInput{
				authorizationHeader: "abcdef",
				existingSession:     &sessionsapi.SessionState{User: "user"},
				expectedSession:     &sessionsapi.SessionState{User: "user"},
			}),
			Entry("Bearer <password>", basicAuthSessionLoaderTableInput{
				authorizationHeader: fmt.Sprintf("Bearer %s", adminPassword),
				existingSession:     nil,
				expectedSession:     nil,
			}),
			Entry("Basic <password>", basicAuthSessionLoaderTableInput{
				authorizationHeader: fmt.Sprintf("Basic %s", adminPassword),
				existingSession:     nil,
				expectedSession:     nil,
			}),
			Entry("Basic Base64(:<password>) (with existing session)", basicAuthSessionLoaderTableInput{
				authorizationHeader: "Basic OlVzRXJPbjNQNDU1",
				existingSession:     &sessionsapi.SessionState{User: "user"},
				expectedSession:     &sessionsapi.SessionState{User: "user"},
			}),
			Entry("Basic Base64(user1:<user1Password>)", basicAuthSessionLoaderTableInput{
				authorizationHeader: "Basic dXNlcjE6VXNFck9uM1A0NTU=",
				existingSession:     nil,
				expectedSession:     &sessionsapi.SessionState{User: "user1"},
			}),
			Entry("Basic Base64(user2:<user1Password>)", basicAuthSessionLoaderTableInput{
				authorizationHeader: "Basic dXNlcjI6VXNFck9uM1A0NTU=",
				existingSession:     nil,
				expectedSession:     nil,
			}),
			Entry("Basic Base64(user2:<user2Password>)", basicAuthSessionLoaderTableInput{
				authorizationHeader: "Basic dXNlcjI6dXMzcjJQNDU1VzBSZCE=",
				existingSession:     nil,
				expectedSession:     &sessionsapi.SessionState{User: "user2"},
			}),
			Entry("Basic Base64(admin:<adminPassword>)", basicAuthSessionLoaderTableInput{
				authorizationHeader: "Basic YWRtaW46QWRtMW4xc3RyJHQwcg==",
				existingSession:     nil,
				expectedSession:     &sessionsapi.SessionState{User: "admin"},
			}),
			Entry("Basic with groups", basicAuthSessionLoaderTableInput{
				authorizationHeader: "Basic YWRtaW46QWRtMW4xc3RyJHQwcg==",
				sessionGroups:       []string{"a", "b"},
				existingSession:     nil,
				expectedSession:     &sessionsapi.SessionState{User: "admin", Groups: []string{"a", "b"}},
			}),
			Entry("Basic Base64(user1:<user1Password>) (with PreferEmailToUser)", basicAuthSessionLoaderTableInput{
				authorizationHeader: "Basic dXNlcjE6VXNFck9uM1A0NTU=",
				preferEmail:         true,
				existingSession:     nil,
				expectedSession:     &sessionsapi.SessionState{User: "user1", Email: "user1"},
			}),
		)
	})
})

type fakeBasicValidator struct {
	users map[string]string
}

func (f fakeBasicValidator) Validate(user, password string) bool {
	if f.users == nil {
		return false
	}
	if realPassword, ok := f.users[user]; ok {
		return realPassword == password
	}
	return false
}
