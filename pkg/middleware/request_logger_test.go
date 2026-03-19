package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Request logger suite", func() {
	type expectedFields struct {
		User       string
		Client     string
		Host       string
		Method     string
		URI        string
		Protocol   string
		Upstream   string
		StatusCode float64
		Size       float64
		RequestID  string
	}

	type requestLoggerTableInput struct {
		Expected     *expectedFields // nil means no output expected
		Path         string
		ExcludePaths []string
		Upstream     string
		Session      *sessions.SessionState
	}

	DescribeTable("when service a request",
		func(in *requestLoggerTableInput) {
			buf := bytes.NewBuffer(nil)
			logger.Setup(slog.LevelDebug, "json", buf, buf)
			logger.SetExcludePaths(in.ExcludePaths)

			req, err := http.NewRequest("GET", in.Path, nil)
			Expect(err).ToNot(HaveOccurred())
			req.RemoteAddr = "127.0.0.1"
			req.Host = "test-server"

			scope := &middlewareapi.RequestScope{
				RequestID: "11111111-2222-4333-8444-555555555555",
				Session:   in.Session,
			}
			req = middlewareapi.AddRequestScope(req, scope)

			handler := NewRequestLogger()(testUpstreamHandler(in.Upstream))
			handler.ServeHTTP(httptest.NewRecorder(), req)

			if in.Expected == nil {
				Expect(buf.String()).To(BeEmpty())
				return
			}

			var logEntry map[string]interface{}
			Expect(json.Unmarshal(buf.Bytes(), &logEntry)).To(Succeed())

			Expect(logEntry).To(HaveKeyWithValue("level", "INFO"))
			Expect(logEntry).To(HaveKeyWithValue("msg", "request"))
			Expect(logEntry).To(HaveKey("time"))
			Expect(logEntry).To(HaveKeyWithValue("user", in.Expected.User))
			Expect(logEntry).To(HaveKeyWithValue("client", in.Expected.Client))
			Expect(logEntry).To(HaveKeyWithValue("host", in.Expected.Host))
			Expect(logEntry).To(HaveKeyWithValue("method", in.Expected.Method))
			Expect(logEntry).To(HaveKeyWithValue("uri", in.Expected.URI))
			Expect(logEntry).To(HaveKeyWithValue("protocol", in.Expected.Protocol))
			Expect(logEntry).To(HaveKeyWithValue("upstream", in.Expected.Upstream))
			Expect(logEntry).To(HaveKeyWithValue("status_code", in.Expected.StatusCode))
			Expect(logEntry).To(HaveKeyWithValue("response_size", in.Expected.Size))
			Expect(logEntry).To(HaveKeyWithValue("request_id", in.Expected.RequestID))
			Expect(logEntry).To(HaveKey("duration_s"))
		},
		Entry("standard request", &requestLoggerTableInput{
			Expected: &expectedFields{
				User: "standard.user", Client: "127.0.0.1", Host: "test-server",
				Method: "GET", URI: "/foo/bar", Protocol: "HTTP/1.1",
				Upstream: "standard", StatusCode: 200, Size: 4,
				RequestID: "11111111-2222-4333-8444-555555555555",
			},
			Path:         "/foo/bar",
			ExcludePaths: []string{},
			Upstream:     "standard",
			Session:      &sessions.SessionState{User: "standard.user"},
		}),
		Entry("with unrelated path excluded", &requestLoggerTableInput{
			Expected: &expectedFields{
				User: "unrelated.exclusion", Client: "127.0.0.1", Host: "test-server",
				Method: "GET", URI: "/foo/bar", Protocol: "HTTP/1.1",
				Upstream: "unrelated", StatusCode: 200, Size: 4,
				RequestID: "11111111-2222-4333-8444-555555555555",
			},
			Path:         "/foo/bar",
			ExcludePaths: []string{"/ping"},
			Upstream:     "unrelated",
			Session:      &sessions.SessionState{User: "unrelated.exclusion"},
		}),
		Entry("with path as the sole exclusion", &requestLoggerTableInput{
			Expected:     nil,
			Path:         "/foo/bar",
			ExcludePaths: []string{"/foo/bar"},
		}),
		Entry("ping path", &requestLoggerTableInput{
			Expected: &expectedFields{
				User: "mr.ping", Client: "127.0.0.1", Host: "test-server",
				Method: "GET", URI: "/ping", Protocol: "HTTP/1.1",
				Upstream: "-", StatusCode: 200, Size: 4,
				RequestID: "11111111-2222-4333-8444-555555555555",
			},
			Path:         "/ping",
			ExcludePaths: []string{},
			Upstream:     "",
			Session:      &sessions.SessionState{User: "mr.ping"},
		}),
		Entry("ping path but excluded", &requestLoggerTableInput{
			Expected:     nil,
			Path:         "/ping",
			ExcludePaths: []string{"/ping"},
			Upstream:     "",
			Session:      &sessions.SessionState{User: "mr.ping"},
		}),
		Entry("ping path and excluded in list", &requestLoggerTableInput{
			Expected:     nil,
			Path:         "/ping",
			ExcludePaths: []string{"/foo/bar", "/ping"},
		}),
		Entry("request with no session", &requestLoggerTableInput{
			Expected: &expectedFields{
				User: "-", Client: "127.0.0.1", Host: "test-server",
				Method: "GET", URI: "/foo/bar", Protocol: "HTTP/1.1",
				Upstream: "custom", StatusCode: 200, Size: 4,
				RequestID: "11111111-2222-4333-8444-555555555555",
			},
			Path:         "/foo/bar",
			ExcludePaths: []string{""},
			Upstream:     "custom",
		}),
		Entry("request with user session", &requestLoggerTableInput{
			Expected: &expectedFields{
				User: "custom.format", Client: "127.0.0.1", Host: "test-server",
				Method: "GET", URI: "/foo/bar", Protocol: "HTTP/1.1",
				Upstream: "custom", StatusCode: 200, Size: 4,
				RequestID: "11111111-2222-4333-8444-555555555555",
			},
			Path:         "/foo/bar",
			ExcludePaths: []string{"/ping"},
			Upstream:     "custom",
			Session:      &sessions.SessionState{User: "custom.format"},
		}),
		Entry("request with empty upstream", &requestLoggerTableInput{
			Expected: &expectedFields{
				User: "-", Client: "127.0.0.1", Host: "test-server",
				Method: "GET", URI: "/ping", Protocol: "HTTP/1.1",
				Upstream: "-", StatusCode: 200, Size: 4,
				RequestID: "11111111-2222-4333-8444-555555555555",
			},
			Path:         "/ping",
			ExcludePaths: []string{""},
		}),
		Entry("excluded path not matched", &requestLoggerTableInput{
			Expected:     nil,
			Path:         "/ping",
			ExcludePaths: []string{"/ping"},
		}),
	)
})
