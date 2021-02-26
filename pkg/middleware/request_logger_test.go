package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

const RequestLoggingFormatWithoutTime = "{{.Client}} - {{.Username}} [TIMELESS] {{.Host}} {{.RequestMethod}} {{.Upstream}} {{.RequestURI}} {{.Protocol}} {{.UserAgent}} {{.StatusCode}} {{.ResponseSize}} {{.RequestDuration}}"

var _ = Describe("Request logger suite", func() {
	type requestLoggerTableInput struct {
		Format             string
		ExpectedLogMessage string
		Path               string
		ExcludePaths       []string
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

			rw := NewResponseWriter(httptest.NewRecorder())

			handler := NewRequestLogger()(testHandler())
			handler.ServeHTTP(rw, req)

			Expect(buf.String()).To(Equal(in.ExpectedLogMessage))
		},
		Entry("standard request", &requestLoggerTableInput{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "127.0.0.1 - - [TIMELESS] test-server GET - \"/foo/bar\" HTTP/1.1 \"\" 200 4 0.000\n",
			Path:               "/foo/bar",
			ExcludePaths:       []string{},
		}),
		Entry("with unrelated path excluded", &requestLoggerTableInput{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "127.0.0.1 - - [TIMELESS] test-server GET - \"/foo/bar\" HTTP/1.1 \"\" 200 4 0.000\n",
			Path:               "/foo/bar",
			ExcludePaths:       []string{"/ping"},
		}),
		Entry("with path as the sole exclusion", &requestLoggerTableInput{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "",
			Path:               "/foo/bar",
			ExcludePaths:       []string{"/foo/bar"},
		}),
		Entry("ping path", &requestLoggerTableInput{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "127.0.0.1 - - [TIMELESS] test-server GET - \"/ping\" HTTP/1.1 \"\" 200 4 0.000\n",
			Path:               "/ping",
			ExcludePaths:       []string{},
		}),
		Entry("ping path but excluded", &requestLoggerTableInput{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "",
			Path:               "/ping",
			ExcludePaths:       []string{"/ping"},
		}),
		Entry("ping path and excluded in list", &requestLoggerTableInput{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "",
			Path:               "/ping",
			ExcludePaths:       []string{"/foo/bar", "/ping"},
		}),
		Entry("custom format", &requestLoggerTableInput{
			Format:             "{{.RequestMethod}}",
			ExpectedLogMessage: "GET\n",
			Path:               "/foo/bar",
			ExcludePaths:       []string{""},
		}),
		Entry("custom format with unrelated exclusion", &requestLoggerTableInput{
			Format:             "{{.RequestMethod}}",
			ExpectedLogMessage: "GET\n",
			Path:               "/foo/bar",
			ExcludePaths:       []string{"/ping"},
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
