package upstream

import (
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/middleware"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Static Response Suite", func() {
	const authenticated = "Authenticated"
	var id string

	BeforeEach(func() {
		// Generate a random id before each test to check the upstream
		// is being set correctly in the scope
		idBytes := make([]byte, 16)
		_, err := io.ReadFull(rand.Reader, idBytes)
		Expect(err).ToNot(HaveOccurred())
		id = string(idBytes)
	})

	type serveHTTPTableInput struct {
		requestPath  string
		staticCode   int
		expectedBody string
		expectedCode int
	}

	DescribeTable("staticResponse ServeHTTP",
		func(in *serveHTTPTableInput) {
			var code *int
			if in.staticCode != 0 {
				code = &in.staticCode
			}

			var scope *middlewareapi.RequestScope
			// Extract the scope so that we can see that the upstream has been set
			// correctly
			extractScope := func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
					scope = middleware.GetRequestScope(req)
					next.ServeHTTP(rw, req)
				})
			}

			handler := alice.New(middleware.NewScope(), extractScope).Then(newStaticResponseHandler(id, code))

			req := httptest.NewRequest("", in.requestPath, nil)
			rw := httptest.NewRecorder()
			handler.ServeHTTP(rw, req)

			Expect(scope.Upstream).To(Equal(id))
			Expect(rw.Code).To(Equal(in.expectedCode))
			Expect(rw.Body.String()).To(Equal(in.expectedBody))
		},
		Entry("with no given code", &serveHTTPTableInput{
			requestPath:  "/",
			staticCode:   0, // Placeholder for nil
			expectedBody: authenticated,
			expectedCode: http.StatusOK,
		}),
		Entry("with status OK", &serveHTTPTableInput{
			requestPath:  "/abc",
			staticCode:   http.StatusOK,
			expectedBody: authenticated,
			expectedCode: http.StatusOK,
		}),
		Entry("with status NoContent", &serveHTTPTableInput{
			requestPath:  "/def",
			staticCode:   http.StatusNoContent,
			expectedBody: authenticated,
			expectedCode: http.StatusNoContent,
		}),
		Entry("with status NotFound", &serveHTTPTableInput{
			requestPath:  "/ghi",
			staticCode:   http.StatusNotFound,
			expectedBody: authenticated,
			expectedCode: http.StatusNotFound,
		}),
		Entry("with status Teapot", &serveHTTPTableInput{
			requestPath:  "/jkl",
			staticCode:   http.StatusTeapot,
			expectedBody: authenticated,
			expectedCode: http.StatusTeapot,
		}),
	)
})
