package upstream

import (
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/app/pagewriter"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Proxy Suite", func() {
	type proxyTableInput struct {
		target    string
		response  testHTTPResponse
		upstream  string
		upstreams options.UpstreamConfig
	}

	Context("multiUpstreamProxy", func() {
		DescribeTable("Proxy ServeHTTP",
			func(in *proxyTableInput) {
				sigData := &options.SignatureData{Hash: crypto.SHA256, Key: "secret"}

				writer := &pagewriter.WriterFuncs{
					ProxyErrorFunc: func(rw http.ResponseWriter, _ *http.Request, _ error) {
						rw.WriteHeader(502)
						rw.Write([]byte("Proxy Error"))
					},
				}

				ok := http.StatusOK
				accepted := http.StatusAccepted

				// Allows for specifying settings and even individual upstreams for specific tests and uses the default upstreams/configs otherwise
				upstreams := in.upstreams
				if len(in.upstreams.Upstreams) == 0 {
					upstreams.Upstreams = []options.Upstream{
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
							ID:            "rewrite-file-backend",
							Path:          "^/rewrite-files/.*/(.*)$",
							RewriteTarget: "/$1",
							URI:           fmt.Sprintf("file:///%s", filesDir),
						},
						{
							ID:         "static-backend",
							Path:       "/static/",
							Static:     true,
							StaticCode: &ok,
						},
						{
							ID:         "static-backend-no-trailing-slash",
							Path:       "/static",
							Static:     true,
							StaticCode: &accepted,
						},
						{
							ID:         "static-backend-long",
							Path:       "/static/long",
							Static:     true,
							StaticCode: &accepted,
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
						{
							ID:            "backend-with-rewrite-prefix",
							Path:          "^/rewrite-prefix/(.*)",
							RewriteTarget: "/different/backend/path/$1",
							URI:           serverAddr,
						},
						{
							ID:   "double-match-plain",
							Path: "/double-match/",
							URI:  serverAddr,
						},
						{
							ID:            "double-match-rewrite",
							Path:          "^/double-match/(.*)",
							RewriteTarget: "/double-match/rewrite/$1",
							URI:           serverAddr,
						},
						{
							ID:   "unix-upstream",
							Path: "/unix/",
							URI:  unixServerAddr,
						},
					}
				}

				upstreamServer, err := NewProxy(upstreams, sigData, writer)
				Expect(err).ToNot(HaveOccurred())

				req := middlewareapi.AddRequestScope(
					httptest.NewRequest("", in.target, nil),
					&middlewareapi.RequestScope{},
				)
				rw := httptest.NewRecorder()
				// Don't mock the remote Address
				req.RemoteAddr = ""

				upstreamServer.ServeHTTP(rw, req)

				scope := middlewareapi.GetRequestScope(req)
				Expect(scope.Upstream).To(Equal(in.upstream))

				Expect(rw.Code).To(Equal(in.response.code))

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
				if body != nil {
					request := testHTTPRequest{}
					Expect(json.Unmarshal(body, &request)).To(Succeed())
					testSanitizeRequestHeader(request.Header)
					Expect(request).To(Equal(in.response.request))
				}
			},
			Entry("with a request to the HTTP service", &proxyTableInput{
				target: "http://example.localhost/http/1234",
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
				upstream: "http-backend",
			}),
			Entry("with a request to the File backend", &proxyTableInput{
				target: "http://example.localhost/files/foo",
				response: testHTTPResponse{
					code: 200,
					header: map[string][]string{
						contentType: {textPlainUTF8},
					},
					raw: "foo",
				},
				upstream: "file-backend",
			}),
			Entry("with a request to the File backend with rewrite", &proxyTableInput{
				target: "http://example.localhost/rewrite-files/anything-at-all/foo",
				response: testHTTPResponse{
					code: 200,
					header: map[string][]string{
						contentType: {textPlainUTF8},
					},
					raw: "foo",
				},
				upstream: "rewrite-file-backend",
			}),
			Entry("with a request to the Static backend", &proxyTableInput{
				target: "http://example.localhost/static/bar",
				response: testHTTPResponse{
					code:   200,
					header: map[string][]string{},
					raw:    "Authenticated",
				},
				upstream: "static-backend",
			}),
			Entry("with a request to the bad HTTP backend", &proxyTableInput{
				target: "http://example.localhost/bad-http/bad",
				response: testHTTPResponse{
					code:   502,
					header: map[string][]string{},
					// This tests the error handler
					raw: "Proxy Error",
				},
				upstream: "bad-http-backend",
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
				target: "http://example.localhost/single-path",
				response: testHTTPResponse{
					code:   200,
					header: map[string][]string{},
					raw:    "Authenticated",
				},
				upstream: "single-path-backend",
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
			Entry("with a request to the rewrite prefix server", &proxyTableInput{
				target: "http://example.localhost/rewrite-prefix/1234",
				response: testHTTPResponse{
					code: 200,
					header: map[string][]string{
						contentType: {applicationJSON},
					},
					request: testHTTPRequest{
						Method: "GET",
						URL:    "http://example.localhost/different/backend/path/1234",
						Header: map[string][]string{
							"Gap-Auth":      {""},
							"Gap-Signature": {"sha256 Pzy0fSFhzbhY0R9rj8vl5LCiIQaKVB0s6h9BADgIT4I="},
						},
						Body:       []byte{},
						Host:       "example.localhost",
						RequestURI: "http://example.localhost/different/backend/path/1234",
					},
				},
				upstream: "backend-with-rewrite-prefix",
			}),
			Entry("with a request to a subpath of the rewrite prefix server", &proxyTableInput{
				target: "http://example.localhost/rewrite-prefix/1234/abc",
				response: testHTTPResponse{
					code: 200,
					header: map[string][]string{
						contentType: {applicationJSON},
					},
					request: testHTTPRequest{
						Method: "GET",
						URL:    "http://example.localhost/different/backend/path/1234/abc",
						Header: map[string][]string{
							"Gap-Auth":      {""},
							"Gap-Signature": {"sha256 uqIAxSgz+onqHDMMl/EAZWbwSw56PzM90iCocNUEqmw="},
						},
						Body:       []byte{},
						Host:       "example.localhost",
						RequestURI: "http://example.localhost/different/backend/path/1234/abc",
					},
				},
				upstream: "backend-with-rewrite-prefix",
			}),
			Entry("with a request to a path, missing the trailing slash", &proxyTableInput{
				target: "http://example.localhost/http",
				response: testHTTPResponse{
					code: 301,
					header: map[string][]string{
						contentType: {textHTMLUTF8},
						"Location":  {"http://example.localhost/http/"},
					},
					raw: "<a href=\"http://example.localhost/http/\">Moved Permanently</a>.\n\n",
				},
			}),
			Entry("with a request to a path, missing the trailing slash, but registered separately", &proxyTableInput{
				target: "http://example.localhost/static",
				response: testHTTPResponse{
					code:   202,
					header: map[string][]string{},
					raw:    "Authenticated",
				},
				upstream: "static-backend-no-trailing-slash",
			}),
			Entry("should match longest path first", &proxyTableInput{
				target: "http://example.localhost/static/long",
				response: testHTTPResponse{
					code:   202,
					header: map[string][]string{},
					raw:    "Authenticated",
				},
				upstream: "static-backend-long",
			}),
			Entry("should match rewrite path first", &proxyTableInput{
				target: "http://example.localhost/double-match/foo",
				response: testHTTPResponse{
					code: 200,
					header: map[string][]string{
						contentType: {applicationJSON},
					},
					request: testHTTPRequest{
						Method: "GET",
						URL:    "http://example.localhost/double-match/rewrite/foo",
						Header: map[string][]string{
							"Gap-Auth":      {""},
							"Gap-Signature": {"sha256 Ii7wKYBkRkJH556gRUsVUwGPgF7IG7V7X4vhkiyzfQ0="},
						},
						Body:       []byte{},
						Host:       "example.localhost",
						RequestURI: "http://example.localhost/double-match/rewrite/foo",
					},
				},
				upstream: "double-match-rewrite",
			}),
			Entry("containing an escaped '/' without ProxyRawPath", &proxyTableInput{
				target: "http://example.localhost/%2F/test1/%2F/test2",
				response: testHTTPResponse{
					code: 301,
					header: map[string][]string{
						"Location": {
							"http://example.localhost/test1/test2",
						},
					},
				},
				upstream: "",
			}),
			Entry("containing an escaped '/' with ProxyRawPath", &proxyTableInput{
				upstreams: options.UpstreamConfig{ProxyRawPath: true},
				target:    "http://example.localhost/%2F/test1/%2F/test2",
				response: testHTTPResponse{
					code: 404,
					header: map[string][]string{
						"X-Content-Type-Options": {"nosniff"},
						contentType:              {textPlainUTF8},
					},
					raw: "404 page not found\n",
				},
				upstream: "",
			}),
			Entry("with a request to the UNIX socket backend", &proxyTableInput{
				target: "http://example.localhost/unix/file",
				response: testHTTPResponse{
					code: 200,
					header: map[string][]string{
						contentType: {applicationJSON},
					},
					request: testHTTPRequest{
						Method: "GET",
						URL:    "http://example.localhost/unix/file",
						Header: map[string][]string{
							"Gap-Auth":      {""},
							"Gap-Signature": {"sha256 4ux8esLj2fw9sTWZwgFhb00bGbw0Fnhed5Fm9jz5Blw="},
						},
						Body:       []byte{},
						Host:       "example.localhost",
						RequestURI: "http://example.localhost/unix/file",
					},
				},
				upstream: "unix-upstream",
			}),
		)
	})

	Context("sortByPathLongest", func() {
		type sortByPathLongestTableInput struct {
			input          []options.Upstream
			expectedOutput []options.Upstream
		}

		httpPath := options.Upstream{
			Path: "/http/",
		}

		httpSubPath := options.Upstream{
			Path: "/http/subpath/",
		}

		longerPath := options.Upstream{
			Path: "/longer-than-http",
		}

		shortPathWithRewrite := options.Upstream{
			Path:          "^/h/(.*)",
			RewriteTarget: "/$1",
		}

		shortSubPathWithRewrite := options.Upstream{
			Path:          "^/h/bar/(.*)",
			RewriteTarget: "/$1",
		}

		DescribeTable("short sort into the correct order",
			func(in sortByPathLongestTableInput) {
				Expect(sortByPathLongest(in.input)).To(Equal(in.expectedOutput))
			},
			Entry("with a mix of paths registered", sortByPathLongestTableInput{
				input:          []options.Upstream{httpPath, httpSubPath, shortSubPathWithRewrite, longerPath, shortPathWithRewrite},
				expectedOutput: []options.Upstream{shortSubPathWithRewrite, shortPathWithRewrite, longerPath, httpSubPath, httpPath},
			}),
			Entry("when a subpath is registered (in order)", sortByPathLongestTableInput{
				input:          []options.Upstream{httpSubPath, httpPath},
				expectedOutput: []options.Upstream{httpSubPath, httpPath},
			}),
			Entry("when a subpath is registered (out of order)", sortByPathLongestTableInput{
				input:          []options.Upstream{httpPath, httpSubPath},
				expectedOutput: []options.Upstream{httpSubPath, httpPath},
			}),
			Entry("when longer paths are registered (in order)", sortByPathLongestTableInput{
				input:          []options.Upstream{longerPath, httpPath},
				expectedOutput: []options.Upstream{longerPath, httpPath},
			}),
			Entry("when longer paths are registered (out of order)", sortByPathLongestTableInput{
				input:          []options.Upstream{httpPath, longerPath},
				expectedOutput: []options.Upstream{longerPath, httpPath},
			}),
			Entry("when a rewrite target is registered (in order)", sortByPathLongestTableInput{
				input:          []options.Upstream{shortPathWithRewrite, longerPath},
				expectedOutput: []options.Upstream{shortPathWithRewrite, longerPath},
			}),
			Entry("when a rewrite target is registered (out of order)", sortByPathLongestTableInput{
				input:          []options.Upstream{longerPath, shortPathWithRewrite},
				expectedOutput: []options.Upstream{shortPathWithRewrite, longerPath},
			}),
			Entry("with multiple rewrite targets registered (in order)", sortByPathLongestTableInput{
				input:          []options.Upstream{shortSubPathWithRewrite, shortPathWithRewrite},
				expectedOutput: []options.Upstream{shortSubPathWithRewrite, shortPathWithRewrite},
			}),
			Entry("with multiple rewrite targets registered (out of order)", sortByPathLongestTableInput{
				input:          []options.Upstream{shortPathWithRewrite, shortSubPathWithRewrite},
				expectedOutput: []options.Upstream{shortSubPathWithRewrite, shortPathWithRewrite},
			}),
		)
	})
})
