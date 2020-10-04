package upstream

import (
	"crypto"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/middleware"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Proxy Suite", func() {
	var upstreamServer http.Handler
	var scope *middlewareapi.RequestScope

	BeforeEach(func() {
		sigData := &options.SignatureData{Hash: crypto.SHA256, Key: "secret"}

		tmpl, err := template.New("").Parse("{{ .Title }}\n{{ .Message }}\n{{ .ProxyPrefix }}")
		Expect(err).ToNot(HaveOccurred())
		errorHandler := NewProxyErrorHandler(tmpl, "prefix")

		ok := http.StatusOK

		upstreams := options.Upstreams{
			{
				ID:   "http-backend",
				Path: "/http/",
				URI:  serverAddr,
			},
			{
				ID:   "file-backend",
				Path: "/files/",
				URI:  fmt.Sprintf("file:///%s", filesDir),
			},
			{
				ID:         "static-backend",
				Path:       "/static/",
				Static:     true,
				StaticCode: &ok,
			},
			{
				ID:   "bad-http-backend",
				Path: "/bad-http/",
				URI:  "http://::1",
			},
			{
				ID:         "single-path-backend",
				Path:       "/single-path",
				Static:     true,
				StaticCode: &ok,
			},
		}

		proxyServer, err := NewProxy(upstreams, sigData, errorHandler)
		Expect(err).ToNot(HaveOccurred())

		scope = nil
		// Extract the scope so that we can see that the upstream has been set
		// correctly
		extractScope := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				scope = middleware.GetRequestScope(req)
				next.ServeHTTP(rw, req)
			})
		}

		upstreamServer = alice.New(middleware.NewScope(), extractScope).Then(proxyServer)
	})

	type proxyTableInput struct {
		target   string
		upstream string
		response testHTTPResponse
	}

	DescribeTable("Proxy ServerHTTP",
		func(in *proxyTableInput) {
			req := httptest.NewRequest("", in.target, nil)
			rw := httptest.NewRecorder()
			// Don't mock the remote Address
			req.RemoteAddr = ""

			upstreamServer.ServeHTTP(rw, req)

			Expect(rw.Code).To(Equal(in.response.code))
			Expect(scope.Upstream).To(Equal(in.upstream))

			// Delete extra headers that aren't relevant to tests
			testSanitizeResponseHeader(rw.Header())
			Expect(rw.Header()).To(Equal(in.response.header))

			body := rw.Body.Bytes()
			// If the raw body is set, check that, else check the Request object
			if in.response.raw != "" {
				Expect(string(body)).To(Equal(in.response.raw))
				return
			}

			// Compare the reflected request to the upstream
			request := testHTTPRequest{}
			Expect(json.Unmarshal(body, &request)).To(Succeed())
			testSanitizeRequestHeader(request.Header)
			Expect(request).To(Equal(in.response.request))
		},
		Entry("with a request to the HTTP service", &proxyTableInput{
			target:   "http://example.localhost/http/1234",
			upstream: "http-backend",
			response: testHTTPResponse{
				code: 200,
				header: map[string][]string{
					contentType: {applicationJSON},
				},
				request: testHTTPRequest{
					Method: "GET",
					URL:    "http://example.localhost/http/1234",
					Header: map[string][]string{
						"Gap-Auth":      {""},
						"Gap-Signature": {"sha256 ofB1u6+FhEUbFLc3/uGbJVkl7GaN4egFqVvyO3+2I1w="},
					},
					Body:       []byte{},
					Host:       "example.localhost",
					RequestURI: "http://example.localhost/http/1234",
				},
			},
		}),
		Entry("with a request to the File backend", &proxyTableInput{
			target:   "http://example.localhost/files/foo",
			upstream: "file-backend",
			response: testHTTPResponse{
				code: 200,
				header: map[string][]string{
					contentType: {textPlainUTF8},
				},
				raw: "foo",
			},
		}),
		Entry("with a request to the Static backend", &proxyTableInput{
			target:   "http://example.localhost/static/bar",
			upstream: "static-backend",
			response: testHTTPResponse{
				code:   200,
				header: map[string][]string{},
				raw:    "Authenticated",
			},
		}),
		Entry("with a request to the bad HTTP backend", &proxyTableInput{
			target:   "http://example.localhost/bad-http/bad",
			upstream: "bad-http-backend",
			response: testHTTPResponse{
				code:   502,
				header: map[string][]string{},
				// This tests the error handler
				raw: "Bad Gateway\nError proxying to upstream server\nprefix",
			},
		}),
		Entry("with a request to the to an unregistered path", &proxyTableInput{
			target: "http://example.localhost/unregistered",
			response: testHTTPResponse{
				code: 404,
				header: map[string][]string{
					"X-Content-Type-Options": {"nosniff"},
					contentType:              {textPlainUTF8},
				},
				raw: "404 page not found\n",
			},
		}),
		Entry("with a request to the to backend registered to a single path", &proxyTableInput{
			target:   "http://example.localhost/single-path",
			upstream: "single-path-backend",
			response: testHTTPResponse{
				code:   200,
				header: map[string][]string{},
				raw:    "Authenticated",
			},
		}),
		Entry("with a request to the to a subpath of a backend registered to a single path", &proxyTableInput{
			target: "http://example.localhost/single-path/unregistered",
			response: testHTTPResponse{
				code: 404,
				header: map[string][]string{
					"X-Content-Type-Options": {"nosniff"},
					contentType:              {textPlainUTF8},
				},
				raw: "404 page not found\n",
			},
		}),
	)
})
