package middleware

import (
	"crypto/tls"
	"fmt"
	"net/http/httptest"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("RedirectToHTTPS suite", func() {
	const httpsPort = "8443"

	var permanentRedirectBody = func(address string) string {
		return fmt.Sprintf("<a href=\"%s\">Permanent Redirect</a>.\n\n", address)
	}

	type requestTableInput struct {
		requestString    string
		useTLS           bool
		headers          map[string]string
		reverseProxy     bool
		expectedStatus   int
		expectedBody     string
		expectedLocation string
	}

	DescribeTable("when serving a request",
		func(in *requestTableInput) {
			req := httptest.NewRequest("", in.requestString, nil)
			for k, v := range in.headers {
				req.Header.Add(k, v)
			}
			if in.useTLS {
				req.TLS = &tls.ConnectionState{}
			}
			scope := &middlewareapi.RequestScope{
				ReverseProxy: in.reverseProxy,
			}
			req = middlewareapi.AddRequestScope(req, scope)

			rw := httptest.NewRecorder()

			handler := NewRedirectToHTTPS(httpsPort)(testHandler())
			handler.ServeHTTP(rw, req)

			Expect(rw.Code).To(Equal(in.expectedStatus))
			Expect(rw.Body.String()).To(Equal(in.expectedBody))

			if in.expectedLocation != "" {
				Expect(rw.Header().Values("Location")).To(ConsistOf(in.expectedLocation))
			}
		},
		Entry("without TLS", &requestTableInput{
			requestString:    "http://example.com",
			useTLS:           false,
			headers:          map[string]string{},
			reverseProxy:     false,
			expectedStatus:   308,
			expectedBody:     permanentRedirectBody("https://example.com"),
			expectedLocation: "https://example.com",
		}),
		Entry("with TLS", &requestTableInput{
			requestString:  "https://example.com",
			useTLS:         true,
			headers:        map[string]string{},
			reverseProxy:   false,
			expectedStatus: 200,
			expectedBody:   "test",
		}),
		Entry("without TLS and X-Forwarded-Proto=HTTPS", &requestTableInput{
			requestString: "http://example.com",
			useTLS:        false,
			headers: map[string]string{
				"X-Forwarded-Proto": "HTTPS",
			},
			reverseProxy:   true,
			expectedStatus: 200,
			expectedBody:   "test",
		}),
		Entry("without TLS and X-Forwarded-Proto=HTTPS but ReverseProxy not set", &requestTableInput{
			requestString: "http://example.com",
			useTLS:        false,
			headers: map[string]string{
				"X-Forwarded-Proto": "HTTPS",
			},
			reverseProxy:     false,
			expectedStatus:   308,
			expectedBody:     permanentRedirectBody("https://example.com"),
			expectedLocation: "https://example.com",
		}),
		Entry("with TLS and X-Forwarded-Proto=HTTPS", &requestTableInput{
			requestString: "https://example.com",
			useTLS:        true,
			headers: map[string]string{
				"X-Forwarded-Proto": "HTTPS",
			},
			reverseProxy:   true,
			expectedStatus: 200,
			expectedBody:   "test",
		}),
		Entry("without TLS and X-Forwarded-Proto=https", &requestTableInput{
			requestString: "http://example.com",
			useTLS:        false,
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
			},
			reverseProxy:   true,
			expectedStatus: 200,
			expectedBody:   "test",
		}),
		Entry("with TLS and X-Forwarded-Proto=https", &requestTableInput{
			requestString: "https://example.com",
			useTLS:        true,
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
			},
			reverseProxy:   true,
			expectedStatus: 200,
			expectedBody:   "test",
		}),
		Entry("without TLS and X-Forwarded-Proto=HTTP", &requestTableInput{
			requestString: "http://example.com",
			useTLS:        false,
			headers: map[string]string{
				"X-Forwarded-Proto": "HTTP",
			},
			reverseProxy:     true,
			expectedStatus:   308,
			expectedBody:     permanentRedirectBody("https://example.com"),
			expectedLocation: "https://example.com",
		}),
		Entry("with TLS and X-Forwarded-Proto=HTTP", &requestTableInput{
			requestString: "https://example.com",
			useTLS:        true,
			headers: map[string]string{
				"X-Forwarded-Proto": "HTTP",
			},
			reverseProxy:     true,
			expectedStatus:   308,
			expectedBody:     permanentRedirectBody("https://example.com"),
			expectedLocation: "https://example.com",
		}),
		Entry("without TLS and X-Forwarded-Proto=http", &requestTableInput{
			requestString: "https://example.com",
			useTLS:        false,
			headers: map[string]string{
				"X-Forwarded-Proto": "http",
			},
			reverseProxy:     true,
			expectedStatus:   308,
			expectedBody:     permanentRedirectBody("https://example.com"),
			expectedLocation: "https://example.com",
		}),
		Entry("with TLS and X-Forwarded-Proto=http", &requestTableInput{
			requestString: "https://example.com",
			useTLS:        true,
			headers: map[string]string{
				"X-Forwarded-Proto": "http",
			},
			reverseProxy:     true,
			expectedStatus:   308,
			expectedBody:     permanentRedirectBody("https://example.com"),
			expectedLocation: "https://example.com",
		}),
		Entry("without TLS on a non-standard port", &requestTableInput{
			requestString:    "http://example.com:8080",
			useTLS:           false,
			headers:          map[string]string{},
			reverseProxy:     false,
			expectedStatus:   308,
			expectedBody:     permanentRedirectBody("https://example.com:8443"),
			expectedLocation: "https://example.com:8443",
		}),
		Entry("with TLS on a non-standard port", &requestTableInput{
			requestString:  "https://example.com:8443",
			useTLS:         true,
			headers:        map[string]string{},
			reverseProxy:   false,
			expectedStatus: 200,
			expectedBody:   "test",
		}),
		// By using newRequest from httptest we get example.com as a Host
		// when the target is just a path.
		// For details: https://golang.org/pkg/net/http/httptest/#NewRequest
		Entry("without TLS with a path as request", &requestTableInput{
			requestString:    "/",
			useTLS:           false,
			expectedStatus:   308,
			reverseProxy:     false,
			expectedBody:     permanentRedirectBody("https://example.com/"),
			expectedLocation: "https://example.com/",
		}),
		Entry("without TLS with an X-Forwarded-Host header", &requestTableInput{
			requestString: "http://internal.example.com",
			useTLS:        false,
			headers: map[string]string{
				"X-Forwarded-Proto": "HTTP",
				"X-Forwarded-Host":  "external.example.com",
			},
			reverseProxy:     true,
			expectedStatus:   308,
			expectedBody:     permanentRedirectBody("https://external.example.com"),
			expectedLocation: "https://external.example.com",
		}),
	)
})
