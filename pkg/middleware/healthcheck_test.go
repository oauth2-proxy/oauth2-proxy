package middleware

import (
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("HealthCheck suite", func() {
	type requestTableInput struct {
		healthCheckPaths      []string
		healthCheckUserAgents []string
		requestString         string
		headers               map[string]string
		expectedStatus        int
		expectedBody          string
	}

	DescribeTable("when serving a request",
		func(in *requestTableInput) {
			req := httptest.NewRequest("", in.requestString, nil)
			for k, v := range in.headers {
				req.Header.Add(k, v)
			}

			rw := httptest.NewRecorder()

			handler := NewHealthCheck(in.healthCheckPaths, in.healthCheckUserAgents)(http.NotFoundHandler())
			handler.ServeHTTP(rw, req)

			Expect(rw.Code).To(Equal(in.expectedStatus))
			Expect(rw.Body.String()).To(Equal(in.expectedBody))
		},
		Entry("when no health check paths are configured", &requestTableInput{
			healthCheckPaths:      []string{},
			healthCheckUserAgents: []string{"hc/1.0"},
			requestString:         "http://example.com/ping",
			headers:               map[string]string{},
			expectedStatus:        404,
			expectedBody:          "404 page not found\n",
		}),
		Entry("when requesting the healthcheck path", &requestTableInput{
			healthCheckPaths:      []string{"/ping"},
			healthCheckUserAgents: []string{"hc/1.0"},
			requestString:         "http://example.com/ping",
			headers:               map[string]string{},
			expectedStatus:        200,
			expectedBody:          "OK",
		}),
		Entry("when requesting a different path", &requestTableInput{
			healthCheckPaths:      []string{"/ping"},
			healthCheckUserAgents: []string{"hc/1.0"},
			requestString:         "http://example.com/different",
			headers:               map[string]string{},
			expectedStatus:        404,
			expectedBody:          "404 page not found\n",
		}),
		Entry("when a blank string is configured as a health check path and the request has no specific path", &requestTableInput{
			healthCheckPaths:      []string{""},
			healthCheckUserAgents: []string{"hc/1.0"},
			requestString:         "http://example.com",
			headers:               map[string]string{},
			expectedStatus:        404,
			expectedBody:          "404 page not found\n",
		}),
		Entry("with no health check user agents configured", &requestTableInput{
			healthCheckPaths:      []string{"/ping"},
			healthCheckUserAgents: []string{},
			requestString:         "http://example.com/abc",
			headers: map[string]string{
				"User-Agent": "user",
			},
			expectedStatus: 404,
			expectedBody:   "404 page not found\n",
		}),
		Entry("with a request from a different user agent", &requestTableInput{
			healthCheckPaths:      []string{"/ping"},
			healthCheckUserAgents: []string{"hc/1.0"},
			requestString:         "http://example.com/abc",
			headers: map[string]string{
				"User-Agent": "different",
			},
			expectedStatus: 404,
			expectedBody:   "404 page not found\n",
		}),
		Entry("with a request from the health check user agent", &requestTableInput{
			healthCheckPaths:      []string{"/ping"},
			healthCheckUserAgents: []string{"hc/1.0"},
			requestString:         "http://example.com/abc",
			headers: map[string]string{
				"User-Agent": "hc/1.0",
			},
			expectedStatus: 200,
			expectedBody:   "OK",
		}),
		Entry("when a blank string is configured as a health check agent and a request has no user agent", &requestTableInput{
			healthCheckPaths:      []string{"/ping"},
			healthCheckUserAgents: []string{""},
			requestString:         "http://example.com/abc",
			headers:               map[string]string{},
			expectedStatus:        404,
			expectedBody:          "404 page not found\n",
		}),
		Entry("with multiple paths, request one of the healthcheck paths", &requestTableInput{
			healthCheckPaths:      []string{"/ping", "/liveness_check", "/readiness_check"},
			healthCheckUserAgents: []string{"hc/1.0"},
			requestString:         "http://example.com/readiness_check",
			headers:               map[string]string{},
			expectedStatus:        200,
			expectedBody:          "OK",
		}),
		Entry("with multiple paths, request none of the healthcheck paths", &requestTableInput{
			healthCheckPaths:      []string{"/ping", "/liveness_check", "/readiness_check"},
			healthCheckUserAgents: []string{"hc/1.0"},
			requestString:         "http://example.com/readiness",
			headers: map[string]string{
				"User-Agent": "user",
			},
			expectedStatus: 404,
			expectedBody:   "404 page not found\n",
		}),
		Entry("with multiple user agents, request from a health check user agent", &requestTableInput{
			healthCheckPaths:      []string{"/ping"},
			healthCheckUserAgents: []string{"hc/1.0", "GoogleHC/1.0"},
			requestString:         "http://example.com/abc",
			headers: map[string]string{
				"User-Agent": "GoogleHC/1.0",
			},
			expectedStatus: 200,
			expectedBody:   "OK",
		}),
		Entry("with multiple user agents, request from none of the health check user agents", &requestTableInput{
			healthCheckPaths:      []string{"/ping"},
			healthCheckUserAgents: []string{"hc/1.0", "GoogleHC/1.0"},
			requestString:         "http://example.com/abc",
			headers: map[string]string{
				"User-Agent": "user",
			},
			expectedStatus: 404,
			expectedBody:   "404 page not found\n",
		}),
	)
})
