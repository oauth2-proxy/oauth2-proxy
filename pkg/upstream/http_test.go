package upstream

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/middleware"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/net/websocket"
)

var _ = Describe("HTTP Upstream Suite", func() {
	defaultFlushInterval := options.Duration(options.DefaultUpstreamFlushInterval)
	defaultTimeout := options.Duration(options.DefaultUpstreamTimeout)
	truth := true
	falsum := false

	type httpUpstreamTableInput struct {
		id                     string
		serverAddr             *string
		target                 string
		method                 string
		body                   []byte
		passUpstreamHostHeader bool
		signatureData          *options.SignatureData
		existingHeaders        map[string]string
		expectedResponse       testHTTPResponse
		expectedUpstream       string
		errorHandler           ProxyErrorHandler
	}

	DescribeTable("HTTP Upstream ServeHTTP",
		func(in *httpUpstreamTableInput) {
			buf := bytes.NewBuffer(in.body)
			req := httptest.NewRequest(in.method, in.target, buf)
			// Don't mock the remote Address
			req.RemoteAddr = ""

			for key, value := range in.existingHeaders {
				req.Header.Add(key, value)
			}
			if host := req.Header.Get("Host"); host != "" {
				req.Host = host
			}

			req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})
			rw := httptest.NewRecorder()

			flush := options.Duration(1 * time.Second)

			timeout := options.Duration(options.DefaultUpstreamTimeout)

			upstream := options.Upstream{
				ID:                    in.id,
				PassHostHeader:        &in.passUpstreamHostHeader,
				ProxyWebSockets:       &falsum,
				InsecureSkipTLSVerify: false,
				FlushInterval:         &flush,
				Timeout:               &timeout,
			}

			Expect(in.serverAddr).ToNot(BeNil())
			u, err := url.Parse(*in.serverAddr)
			Expect(err).ToNot(HaveOccurred())

			handler := newHTTPUpstreamProxy(upstream, u, in.signatureData, in.errorHandler)
			handler.ServeHTTP(rw, req)

			Expect(rw.Code).To(Equal(in.expectedResponse.code))

			scope := middlewareapi.GetRequestScope(req)
			Expect(scope.Upstream).To(Equal(in.expectedUpstream))

			// Delete extra headers that aren't relevant to tests
			testSanitizeResponseHeader(rw.Header())
			Expect(rw.Header()).To(Equal(in.expectedResponse.header))

			body := rw.Body.Bytes()
			if in.expectedResponse.raw != "" || rw.Code != http.StatusOK {
				Expect(string(body)).To(Equal(in.expectedResponse.raw))
				return
			}

			// Compare the reflected request to the upstream
			request := testHTTPRequest{}
			Expect(json.Unmarshal(body, &request)).To(Succeed())
			testSanitizeRequestHeader(request.Header)
			Expect(request).To(Equal(in.expectedResponse.request))
		},
		Entry("request a path on the server", &httpUpstreamTableInput{
			id:           "default",
			serverAddr:   &serverAddr,
			target:       "http://example.localhost/foo",
			method:       "GET",
			body:         []byte{},
			errorHandler: nil,
			expectedResponse: testHTTPResponse{
				code: 200,
				header: map[string][]string{
					contentType: {applicationJSON},
				},
				request: testHTTPRequest{
					Method:     "GET",
					URL:        "http://example.localhost/foo",
					Header:     map[string][]string{},
					Body:       []byte{},
					Host:       "example.localhost",
					RequestURI: "http://example.localhost/foo",
				},
			},
			expectedUpstream: "default",
		}),
		Entry("request a path with encoded slashes", &httpUpstreamTableInput{
			id:           "encodedSlashes",
			serverAddr:   &serverAddr,
			target:       "http://example.localhost/foo%2fbar/?baz=1",
			method:       "GET",
			body:         []byte{},
			errorHandler: nil,
			expectedResponse: testHTTPResponse{
				code: 200,
				header: map[string][]string{
					contentType: {applicationJSON},
				},
				request: testHTTPRequest{
					Method:     "GET",
					URL:        "http://example.localhost/foo%2fbar/?baz=1",
					Header:     map[string][]string{},
					Body:       []byte{},
					Host:       "example.localhost",
					RequestURI: "http://example.localhost/foo%2fbar/?baz=1",
				},
			},
			expectedUpstream: "encodedSlashes",
		}),
		Entry("request a path with an empty query string", &httpUpstreamTableInput{
			id:           "default",
			serverAddr:   &serverAddr,
			target:       "http://example.localhost/foo?",
			method:       "GET",
			body:         []byte{},
			errorHandler: nil,
			expectedResponse: testHTTPResponse{
				code: 200,
				header: map[string][]string{
					contentType: {applicationJSON},
				},
				request: testHTTPRequest{
					Method:     "GET",
					URL:        "http://example.localhost/foo?",
					Header:     map[string][]string{},
					Body:       []byte{},
					Host:       "example.localhost",
					RequestURI: "http://example.localhost/foo?",
				},
			},
			expectedUpstream: "default",
		}),
		Entry("when the request has a body", &httpUpstreamTableInput{
			id:           "requestWithBody",
			serverAddr:   &serverAddr,
			target:       "http://example.localhost/withBody",
			method:       "POST",
			body:         []byte("body"),
			errorHandler: nil,
			expectedResponse: testHTTPResponse{
				code: 200,
				header: map[string][]string{
					contentType: {applicationJSON},
				},
				request: testHTTPRequest{
					Method: "POST",
					URL:    "http://example.localhost/withBody",
					Header: map[string][]string{
						contentLength: {"4"},
					},
					Body:       []byte("body"),
					Host:       "example.localhost",
					RequestURI: "http://example.localhost/withBody",
				},
			},
			expectedUpstream: "requestWithBody",
		}),
		Entry("when the upstream is unavailable", &httpUpstreamTableInput{
			id:           "unavailableUpstream",
			serverAddr:   &invalidServer,
			target:       "http://example.localhost/unavailableUpstream",
			method:       "GET",
			body:         []byte{},
			errorHandler: nil,
			expectedResponse: testHTTPResponse{
				code:    502,
				header:  map[string][]string{},
				request: testHTTPRequest{},
			},
			expectedUpstream: "unavailableUpstream",
		}),
		Entry("when the upstream is unavailable and an error handler is set", &httpUpstreamTableInput{
			id:         "withErrorHandler",
			serverAddr: &invalidServer,
			target:     "http://example.localhost/withErrorHandler",
			method:     "GET",
			body:       []byte{},
			errorHandler: func(rw http.ResponseWriter, _ *http.Request, _ error) {
				rw.WriteHeader(502)
				rw.Write([]byte("error"))
			},
			expectedResponse: testHTTPResponse{
				code:    502,
				header:  map[string][]string{},
				raw:     "error",
				request: testHTTPRequest{},
			},
			expectedUpstream: "withErrorHandler",
		}),
		Entry("with a signature", &httpUpstreamTableInput{
			id:         "withSignature",
			serverAddr: &serverAddr,
			target:     "http://example.localhost/withSignature",
			method:     "GET",
			body:       []byte{},
			signatureData: &options.SignatureData{
				Hash: crypto.SHA256,
				Key:  "key",
			},
			errorHandler: nil,
			expectedResponse: testHTTPResponse{
				code: 200,
				header: map[string][]string{
					contentType: {applicationJSON},
				},
				request: testHTTPRequest{
					Method: "GET",
					URL:    "http://example.localhost/withSignature",
					Header: map[string][]string{
						gapAuth:      {""},
						gapSignature: {"sha256 osMWI8Rr0Zr5HgNq6wakrgJITVJQMmFN1fXCesrqrmM="},
					},
					Body:       []byte{},
					Host:       "example.localhost",
					RequestURI: "http://example.localhost/withSignature",
				},
			},
			expectedUpstream: "withSignature",
		}),
		Entry("with existing headers", &httpUpstreamTableInput{
			id:           "existingHeaders",
			serverAddr:   &serverAddr,
			target:       "http://example.localhost/existingHeaders",
			method:       "GET",
			body:         []byte{},
			errorHandler: nil,
			existingHeaders: map[string]string{
				"Header1": "value1",
				"Header2": "value2",
			},
			expectedResponse: testHTTPResponse{
				code: 200,
				header: map[string][]string{
					contentType: {applicationJSON},
				},
				request: testHTTPRequest{
					Method: "GET",
					URL:    "http://example.localhost/existingHeaders",
					Header: map[string][]string{
						"Header1": {"value1"},
						"Header2": {"value2"},
					},
					Body:       []byte{},
					Host:       "example.localhost",
					RequestURI: "http://example.localhost/existingHeaders",
				},
			},
			expectedUpstream: "existingHeaders",
		}),
		Entry("when passing the existing host header", &httpUpstreamTableInput{
			id:                     "passExistingHostHeader",
			serverAddr:             &serverAddr,
			target:                 "/existingHostHeader",
			method:                 "GET",
			body:                   []byte{},
			errorHandler:           nil,
			passUpstreamHostHeader: true,
			existingHeaders: map[string]string{
				"Host": "existing-host",
			},
			expectedResponse: testHTTPResponse{
				code: 200,
				header: map[string][]string{
					contentType: {applicationJSON},
				},
				request: testHTTPRequest{
					Method:     "GET",
					URL:        "/existingHostHeader",
					Header:     map[string][]string{},
					Body:       []byte{},
					Host:       "existing-host",
					RequestURI: "/existingHostHeader",
				},
			},
			expectedUpstream: "passExistingHostHeader",
		}),
		Entry("request using UNIX socket upstream", &httpUpstreamTableInput{
			id:           "unix-upstream",
			serverAddr:   &unixServerAddr,
			target:       "http://example.localhost/file",
			method:       "GET",
			body:         []byte{},
			errorHandler: nil,
			expectedResponse: testHTTPResponse{
				code: 200,
				header: map[string][]string{
					contentType: {applicationJSON},
				},
				request: testHTTPRequest{
					Method:     "GET",
					URL:        "http://example.localhost/file",
					Header:     map[string][]string{},
					Body:       []byte{},
					Host:       "example.localhost",
					RequestURI: "http://example.localhost/file",
				},
			},
			expectedUpstream: "unix-upstream",
		}),
	)

	It("ServeHTTP, when not passing a host header", func() {
		req := httptest.NewRequest("", "http://example.localhost/foo", nil)
		req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})
		rw := httptest.NewRecorder()

		upstream := options.Upstream{
			ID:                    "noPassHost",
			PassHostHeader:        &falsum,
			ProxyWebSockets:       &falsum,
			InsecureSkipTLSVerify: false,
			FlushInterval:         &defaultFlushInterval,
			Timeout:               &defaultTimeout,
		}

		u, err := url.Parse(serverAddr)
		Expect(err).ToNot(HaveOccurred())

		handler := newHTTPUpstreamProxy(upstream, u, nil, nil)
		httpUpstream, ok := handler.(*httpUpstreamProxy)
		Expect(ok).To(BeTrue())

		// Override the handler to just run the director and not actually send the request
		requestInterceptor := func(h http.Handler) http.Handler {
			return http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
				proxy, ok := h.(*httputil.ReverseProxy)
				Expect(ok).To(BeTrue())
				proxy.Director(req)
			})
		}
		httpUpstream.handler = requestInterceptor(httpUpstream.handler)

		httpUpstream.ServeHTTP(rw, req)
		Expect(req.Host).To(Equal(strings.TrimPrefix(serverAddr, "http://")))
	})

	type newUpstreamTableInput struct {
		proxyWebSockets bool
		flushInterval   options.Duration
		skipVerify      bool
		sigData         *options.SignatureData
		errorHandler    func(http.ResponseWriter, *http.Request, error)
		timeout         options.Duration
	}

	DescribeTable("newHTTPUpstreamProxy",
		func(in *newUpstreamTableInput) {
			u, err := url.Parse("http://upstream:1234")
			Expect(err).ToNot(HaveOccurred())

			upstream := options.Upstream{
				ID:                    "foo123",
				FlushInterval:         &in.flushInterval,
				InsecureSkipTLSVerify: in.skipVerify,
				ProxyWebSockets:       &in.proxyWebSockets,
				Timeout:               &in.timeout,
			}

			handler := newHTTPUpstreamProxy(upstream, u, in.sigData, in.errorHandler)
			upstreamProxy, ok := handler.(*httpUpstreamProxy)
			Expect(ok).To(BeTrue())

			Expect(upstreamProxy.auth != nil).To(Equal(in.sigData != nil))
			Expect(upstreamProxy.wsHandler != nil).To(Equal(in.proxyWebSockets))
			Expect(upstreamProxy.upstream).To(Equal(upstream.ID))
			Expect(upstreamProxy.handler).ToNot(BeNil())

			proxy, ok := upstreamProxy.handler.(*httputil.ReverseProxy)
			Expect(ok).To(BeTrue())
			Expect(proxy.FlushInterval).To(Equal(in.flushInterval.Duration()))
			transport, ok := proxy.Transport.(*http.Transport)
			Expect(ok).To(BeTrue())
			Expect(transport.ResponseHeaderTimeout).To(Equal(in.timeout.Duration()))
			Expect(proxy.ErrorHandler != nil).To(Equal(in.errorHandler != nil))
			if in.skipVerify {
				Expect(transport.TLSClientConfig.InsecureSkipVerify).To(Equal(true))
			}
		},
		Entry("with proxy websockets", &newUpstreamTableInput{
			proxyWebSockets: true,
			flushInterval:   defaultFlushInterval,
			skipVerify:      false,
			sigData:         nil,
			errorHandler:    nil,
			timeout:         defaultTimeout,
		}),
		Entry("with a non standard flush interval", &newUpstreamTableInput{
			proxyWebSockets: false,
			flushInterval:   options.Duration(5 * time.Second),
			skipVerify:      false,
			sigData:         nil,
			errorHandler:    nil,
			timeout:         defaultTimeout,
		}),
		Entry("with a InsecureSkipTLSVerify", &newUpstreamTableInput{
			proxyWebSockets: false,
			flushInterval:   defaultFlushInterval,
			skipVerify:      true,
			sigData:         nil,
			errorHandler:    nil,
			timeout:         defaultTimeout,
		}),
		Entry("with a SignatureData", &newUpstreamTableInput{
			proxyWebSockets: false,
			flushInterval:   defaultFlushInterval,
			skipVerify:      false,
			sigData:         &options.SignatureData{Hash: crypto.SHA256, Key: "secret"},
			errorHandler:    nil,
			timeout:         defaultTimeout,
		}),
		Entry("with an error handler", &newUpstreamTableInput{
			proxyWebSockets: false,
			flushInterval:   defaultFlushInterval,
			skipVerify:      false,
			sigData:         nil,
			errorHandler: func(rw http.ResponseWriter, req *http.Request, arg3 error) {
				rw.WriteHeader(502)
			},
			timeout: defaultTimeout,
		}),
		Entry("with a non-default timeout", &newUpstreamTableInput{
			proxyWebSockets: false,
			flushInterval:   defaultFlushInterval,
			skipVerify:      false,
			sigData:         nil,
			errorHandler:    nil,
			timeout:         options.Duration(5 * time.Second),
		}),
	)

	Context("with a websocket proxy", func() {
		var proxyServer *httptest.Server

		BeforeEach(func() {
			flush := options.Duration(1 * time.Second)
			timeout := options.Duration(options.DefaultUpstreamTimeout)
			upstream := options.Upstream{
				ID:                    "websocketProxy",
				PassHostHeader:        &truth,
				ProxyWebSockets:       &truth,
				InsecureSkipTLSVerify: false,
				FlushInterval:         &flush,
				Timeout:               &timeout,
			}

			u, err := url.Parse(serverAddr)
			Expect(err).ToNot(HaveOccurred())

			handler := newHTTPUpstreamProxy(upstream, u, nil, nil)

			proxyServer = httptest.NewServer(middleware.NewScope(false, "X-Request-Id")(handler))
		})

		AfterEach(func() {
			proxyServer.Close()
		})

		It("will proxy websockets", func() {
			origin := "http://example.localhost"
			message := "Hello, world!"

			proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyServer.Listener.Addr().String()))
			Expect(err).ToNot(HaveOccurred())

			wsAddr := fmt.Sprintf("ws://%s/", proxyURL.Host)
			ws, err := websocket.Dial(wsAddr, "", origin)
			Expect(err).ToNot(HaveOccurred())

			Expect(websocket.Message.Send(ws, []byte(message))).To(Succeed())
			var response testWebSocketResponse
			Expect(websocket.JSON.Receive(ws, &response)).To(Succeed())
			Expect(response).To(Equal(testWebSocketResponse{
				Message: message,
				Origin:  origin,
			}))
		})

		It("will proxy HTTP requests", func() {
			response, err := http.Get(fmt.Sprintf("http://%s", proxyServer.Listener.Addr().String()))
			Expect(err).ToNot(HaveOccurred())
			Expect(response.StatusCode).To(Equal(200))
		})
	})
})
