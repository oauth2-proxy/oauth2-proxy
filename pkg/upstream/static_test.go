package upstream

import (
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Static Response Suite", func() {
	const authenticated = "Authenticated"
	var id string

	BeforeEach(func() {
		// Generate a random id before each test to check the GAP-Upstream-Address
		// is being set correctly
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
			handler := newStaticResponseHandler(id, code)

			req := httptest.NewRequest("", in.requestPath, nil)
			req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})

			rw := httptest.NewRecorder()
			handler.ServeHTTP(rw, req)

			scope := middlewareapi.GetRequestScope(req)
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
