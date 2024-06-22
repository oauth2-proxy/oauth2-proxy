package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
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

var _ = Describe("Request logger suite when used with structured format setting", func() {
	type requestLoggerTableInputJson struct {
		StructuredFormat   logger.StructuredFormat
		ExpectedLogMessage map[string]interface{}
	}
	type requestLoggerTableInputPlain struct {
		StructuredFormat   logger.StructuredFormat
		Format             string
		ExpectedLogMessage string
	}

	DescribeTable("when service a request with json format setting",
		func(in *requestLoggerTableInputJson) {
			buf := bytes.NewBuffer(nil)
			logger.SetOutput(buf)
			logger.SetExcludePaths([]string{})
			logger.SetStructuredFormat(in.StructuredFormat)
			req, err := http.NewRequest("GET", "/foo/bar", nil)
			Expect(err).ToNot(HaveOccurred())
			req.RemoteAddr = "127.0.0.1"
			req.Host = "test-server"

			scope := &middlewareapi.RequestScope{
				RequestID: "11111111-2222-4333-8444-555555555555",
				Session:   &sessions.SessionState{User: "standard.user"},
			}
			req = middlewareapi.AddRequestScope(req, scope)

			handler := NewRequestLogger()(testUpstreamHandler("standard"))
			handler.ServeHTTP(httptest.NewRecorder(), req)

			logMessage := buf.String()
			expectedMessage := in.ExpectedLogMessage

			var logData map[string]interface{}

			// Unmarshal the log message into maps
			err = json.Unmarshal([]byte(logMessage), &logData)
			Expect(err).ToNot(HaveOccurred())
			// Remove timestamp from the logData and expectedData
			delete(logData, "timestamp")
			delete(expectedMessage, "timestamp")

			Expect(logData).To(Equal(expectedMessage))
		},
		Entry("standard request", &requestLoggerTableInputJson{
			StructuredFormat: logger.JSON,
			ExpectedLogMessage: map[string]interface{}{
				"client":           "127.0.0.1",
				"host":             "test-server",
				"protocol":         "HTTP/1.1",
				"request_id":       "11111111-2222-4333-8444-555555555555",
				"request_duration": "0.000",
				"request_method":   "GET",
				"request_uri":      "\"/foo/bar\"",
				"response_size":    "4",
				"status_code":      "200",
				"upstream":         "standard",
				"user_agent":       "\"\"",
				"username":         "standard.user",
				"timestamp":        "2024/06/22 17:30:00",
			},
		}),
	)

	DescribeTable("when service a request with plain format setting",
		func(in *requestLoggerTableInputPlain) {
			buf := bytes.NewBuffer(nil)
			logger.SetOutput(buf)
			logger.SetExcludePaths([]string{})
			logger.SetStructuredFormat(in.StructuredFormat)
			logger.SetReqTemplate(in.Format)
			req, err := http.NewRequest("GET", "/foo/bar", nil)
			Expect(err).ToNot(HaveOccurred())
			req.RemoteAddr = "127.0.0.1"
			req.Host = "test-server"

			scope := &middlewareapi.RequestScope{
				RequestID: "11111111-2222-4333-8444-555555555555",
				Session:   &sessions.SessionState{User: "standard.user"},
			}
			req = middlewareapi.AddRequestScope(req, scope)

			handler := NewRequestLogger()(testUpstreamHandler("standard"))
			handler.ServeHTTP(httptest.NewRecorder(), req)

			logMessage := buf.String()
			expectedMessage := in.ExpectedLogMessage

			Expect(logMessage).To(Equal(expectedMessage))
		},
		Entry("standard request", &requestLoggerTableInputPlain{
			StructuredFormat:   logger.Plain,
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "127.0.0.1 - 11111111-2222-4333-8444-555555555555 - standard.user [TIMELESS] test-server GET standard \"/foo/bar\" HTTP/1.1 \"\" 200 4 0.000\n",
		}),
	)
})
