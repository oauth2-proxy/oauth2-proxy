package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const RequestLoggingFormatWithoutTime = "{{.Client}} - {{.RequestID}} - {{.Username}} [TIMELESS] {{.Host}} {{.RequestMethod}} {{.Upstream}} {{.RequestURI}} {{.Protocol}} {{.UserAgent}} {{.StatusCode}} {{.ResponseSize}} {{.RequestDuration}}"

var _ = Describe("Request logger suite", func() {
	type requestLoggerTableInput struct {
		Format             string
		ExpectedLogMessage string
		Path               string
		ExcludePaths       []string
		Upstream           string
		Session            *sessions.SessionState
	}

	DescribeTable("when service a request",
		func(in *requestLoggerTableInput) {
			buf := bytes.NewBuffer(nil)
			logger.SetOutput(buf)
			logger.SetReqTemplate(in.Format)
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

			Expect(buf.String()).To(Equal(in.ExpectedLogMessage))
		},
		Entry("standard request", &requestLoggerTableInput{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "127.0.0.1 - 11111111-2222-4333-8444-555555555555 - standard.user [TIMELESS] test-server GET standard \"/foo/bar\" HTTP/1.1 \"\" 200 4 0.000\n",
			Path:               "/foo/bar",
			ExcludePaths:       []string{},
			Upstream:           "standard",
			Session:            &sessions.SessionState{User: "standard.user"},
		}),
		Entry("with unrelated path excluded", &requestLoggerTableInput{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "127.0.0.1 - 11111111-2222-4333-8444-555555555555 - unrelated.exclusion [TIMELESS] test-server GET unrelated \"/foo/bar\" HTTP/1.1 \"\" 200 4 0.000\n",
			Path:               "/foo/bar",
			ExcludePaths:       []string{"/ping"},
			Upstream:           "unrelated",
			Session:            &sessions.SessionState{User: "unrelated.exclusion"},
		}),
		Entry("with path as the sole exclusion", &requestLoggerTableInput{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "",
			Path:               "/foo/bar",
			ExcludePaths:       []string{"/foo/bar"},
		}),
		Entry("ping path", &requestLoggerTableInput{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "127.0.0.1 - 11111111-2222-4333-8444-555555555555 - mr.ping [TIMELESS] test-server GET - \"/ping\" HTTP/1.1 \"\" 200 4 0.000\n",
			Path:               "/ping",
			ExcludePaths:       []string{},
			Upstream:           "",
			Session:            &sessions.SessionState{User: "mr.ping"},
		}),
		Entry("ping path but excluded", &requestLoggerTableInput{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "",
			Path:               "/ping",
			ExcludePaths:       []string{"/ping"},
			Upstream:           "",
			Session:            &sessions.SessionState{User: "mr.ping"},
		}),
		Entry("ping path and excluded in list", &requestLoggerTableInput{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "",
			Path:               "/ping",
			ExcludePaths:       []string{"/foo/bar", "/ping"},
		}),
		Entry("custom format", &requestLoggerTableInput{
			Format:             "{{.RequestMethod}} {{.Username}} {{.Upstream}}",
			ExpectedLogMessage: "GET custom.format custom\n",
			Path:               "/foo/bar",
			ExcludePaths:       []string{""},
			Upstream:           "custom",
			Session:            &sessions.SessionState{User: "custom.format"},
		}),
		Entry("custom format with unrelated exclusion", &requestLoggerTableInput{
			Format:             "{{.RequestMethod}} {{.Username}} {{.Upstream}}",
			ExpectedLogMessage: "GET custom.format custom\n",
			Path:               "/foo/bar",
			ExcludePaths:       []string{"/ping"},
			Upstream:           "custom",
			Session:            &sessions.SessionState{User: "custom.format"},
		}),
		Entry("custom format ping path", &requestLoggerTableInput{
			Format:             "{{.RequestMethod}}",
			ExpectedLogMessage: "GET\n",
			Path:               "/ping",
			ExcludePaths:       []string{""},
		}),
		Entry("custom format ping path excluded", &requestLoggerTableInput{
			Format:             "{{.RequestMethod}}",
			ExpectedLogMessage: "",
			Path:               "/ping",
			ExcludePaths:       []string{"/ping"},
		}),
	)
})
