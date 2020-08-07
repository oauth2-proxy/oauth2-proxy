package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/stretchr/testify/assert"
)

const RequestLoggingFormatWithoutTime = "{{.Client}} - {{.Username}} [TIMELESS] {{.Host}} {{.RequestMethod}} {{.Upstream}} {{.RequestURI}} {{.Protocol}} {{.UserAgent}} {{.StatusCode}} {{.ResponseSize}} {{.RequestDuration}}"

func TestLoggingHandler_ServeHTTP(t *testing.T) {
	tests := []struct {
		Format             string
		ExpectedLogMessage string
		Path               string
		ExcludePaths       []string
	}{
		{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "127.0.0.1 - - [TIMELESS] test-server GET - \"/foo/bar\" HTTP/1.1 \"\" 200 4 0.000\n",
			Path:               "/foo/bar",
			ExcludePaths:       []string{},
		},
		{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "127.0.0.1 - - [TIMELESS] test-server GET - \"/foo/bar\" HTTP/1.1 \"\" 200 4 0.000\n",
			Path:               "/foo/bar",
			ExcludePaths:       []string{},
		},
		{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "127.0.0.1 - - [TIMELESS] test-server GET - \"/foo/bar\" HTTP/1.1 \"\" 200 4 0.000\n",
			Path:               "/foo/bar",
			ExcludePaths:       []string{"/ping"},
		},
		{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "",
			Path:               "/foo/bar",
			ExcludePaths:       []string{"/foo/bar"},
		},
		{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "127.0.0.1 - - [TIMELESS] test-server GET - \"/ping\" HTTP/1.1 \"\" 200 4 0.000\n",
			Path:               "/ping",
			ExcludePaths:       []string{},
		},
		{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "",
			Path:               "/ping",
			ExcludePaths:       []string{"/ping"},
		},
		{
			Format:             RequestLoggingFormatWithoutTime,
			ExpectedLogMessage: "",
			Path:               "/ping",
			ExcludePaths:       []string{"/foo/bar", "/ping"},
		},
		{
			Format:             "{{.RequestMethod}}",
			ExpectedLogMessage: "GET\n",
			Path:               "/foo/bar",
			ExcludePaths:       []string{""},
		},
		{
			Format:             "{{.RequestMethod}}",
			ExpectedLogMessage: "GET\n",
			Path:               "/foo/bar",
			ExcludePaths:       []string{"/ping"},
		},
		{
			Format:             "{{.RequestMethod}}",
			ExpectedLogMessage: "GET\n",
			Path:               "/ping",
			ExcludePaths:       []string{""},
		},
		{
			Format:             "{{.RequestMethod}}",
			ExpectedLogMessage: "",
			Path:               "/ping",
			ExcludePaths:       []string{"/ping"},
		},
	}

	for _, test := range tests {
		buf := bytes.NewBuffer(nil)
		handler := func(w http.ResponseWriter, req *http.Request) {
			_, ok := w.(http.Hijacker)
			if !ok {
				t.Error("http.Hijacker is not available")
			}

			_, err := w.Write([]byte("test"))
			assert.NoError(t, err)
		}

		logger.SetOutput(buf)
		logger.SetReqTemplate(test.Format)
		logger.SetExcludePaths(test.ExcludePaths)
		h := LoggingHandler(http.HandlerFunc(handler))

		r, _ := http.NewRequest("GET", test.Path, nil)
		r.RemoteAddr = "127.0.0.1"
		r.Host = "test-server"

		h.ServeHTTP(httptest.NewRecorder(), r)

		actual := buf.String()
		assert.Equal(t, test.ExpectedLogMessage, actual)
	}
}
