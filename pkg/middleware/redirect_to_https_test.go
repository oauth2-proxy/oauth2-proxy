package middleware

import (
	"crypto/tls"
	"fmt"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
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
			expectedStatus:   308,
			expectedBody:     permanentRedirectBody("https://example.com"),
			expectedLocation: "https://example.com",
		}),
		Entry("with TLS", &requestTableInput{
			requestString:  "https://example.com",
			useTLS:         true,
			headers:        map[string]string{},
			expectedStatus: 200,
			expectedBody:   "test",
		}),
		Entry("without TLS and X-Forwarded-Proto=HTTPS", &requestTableInput{
			requestString: "http://example.com",
			useTLS:        false,
			headers: map[string]string{
				"X-Forwarded-Proto": "HTTPS",
			},
			expectedStatus: 200,
			expectedBody:   "test",
		}),
		Entry("with TLS and X-Forwarded-Proto=HTTPS", &requestTableInput{
			requestString: "https://example.com",
			useTLS:        true,
			headers: map[string]string{
				"X-Forwarded-Proto": "HTTPS",
			},
			expectedStatus: 200,
			expectedBody:   "test",
		}),
		Entry("without TLS and X-Forwarded-Proto=https", &requestTableInput{
			requestString: "http://example.com",
			useTLS:        false,
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
			},
			expectedStatus: 200,
			expectedBody:   "test",
		}),
		Entry("with TLS and X-Forwarded-Proto=https", &requestTableInput{
			requestString: "https://example.com",
			useTLS:        true,
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
			},
			expectedStatus: 200,
			expectedBody:   "test",
		}),
		Entry("without TLS and X-Forwarded-Proto=HTTP", &requestTableInput{
			requestString: "http://example.com",
			useTLS:        false,
			headers: map[string]string{
				"X-Forwarded-Proto": "HTTP",
			},
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
			expectedStatus:   308,
			expectedBody:     permanentRedirectBody("https://example.com"),
			expectedLocation: "https://example.com",
		}),
		Entry("without TLS on a non-standard port", &requestTableInput{
			requestString:    "http://example.com:8080",
			useTLS:           false,
			headers:          map[string]string{},
			expectedStatus:   308,
			expectedBody:     permanentRedirectBody("https://example.com:8443"),
			expectedLocation: "https://example.com:8443",
		}),
		Entry("with TLS on a non-standard port", &requestTableInput{
			requestString:  "https://example.com:8443",
			useTLS:         true,
			headers:        map[string]string{},
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
			expectedBody:     permanentRedirectBody("https://example.com/"),
			expectedLocation: "https://example.com/",
		}),
	)
})
