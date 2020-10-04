package upstream

import (
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/middleware"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("File Server Suite", func() {
	var dir string
	var handler http.Handler
	var id string
	var scope *middlewareapi.RequestScope

	const (
		foo          = "foo"
		bar          = "bar"
		baz          = "baz"
		pageNotFound = "404 page not found\n"
	)

	BeforeEach(func() {
		// Generate a random id before each test to check the upstream
		// is being set correctly in the scope
		idBytes := make([]byte, 16)
		_, err := io.ReadFull(rand.Reader, idBytes)
		Expect(err).ToNot(HaveOccurred())
		id = string(idBytes)

		scope = nil
		// Extract the scope so that we can see that the upstream has been set
		// correctly
		extractScope := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				scope = middleware.GetRequestScope(req)
				next.ServeHTTP(rw, req)
			})
		}

		handler = alice.New(middleware.NewScope(), extractScope).Then(newFileServer(id, "/files", filesDir))
	})

	AfterEach(func() {
		Expect(os.RemoveAll(dir)).To(Succeed())
	})

	DescribeTable("fileServer ServeHTTP",
		func(requestPath string, expectedResponseCode int, expectedBody string) {
			req := httptest.NewRequest("", requestPath, nil)
			rw := httptest.NewRecorder()
			handler.ServeHTTP(rw, req)

			Expect(scope.Upstream).To(Equal(id))
			Expect(rw.Code).To(Equal(expectedResponseCode))
			Expect(rw.Body.String()).To(Equal(expectedBody))
		},
		Entry("for file foo", "/files/foo", 200, foo),
		Entry("for file bar", "/files/bar", 200, bar),
		Entry("for file foo/baz", "/files/subdir/baz", 200, baz),
		Entry("for a non-existent file inside the path", "/files/baz", 404, pageNotFound),
		Entry("for a non-existent file oustide the path", "/baz", 404, pageNotFound),
	)
})
