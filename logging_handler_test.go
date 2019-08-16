package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pusher/oauth2_proxy/pkg/logger"
)

func TestLoggingHandler_ServeHTTP(t *testing.T) {
	ts := time.Now()

	tests := []struct {
		Format,
		ExpectedLogMessage,
		Path string
		ExcludePaths       []string
		SilencePingLogging bool
	}{
		{logger.DefaultRequestLoggingFormat, fmt.Sprintf("127.0.0.1 - - [%s] test-server GET - \"/foo/bar\" HTTP/1.1 \"\" 200 4 0.000\n", logger.FormatTimestamp(ts)), "/foo/bar", []string{}, false},
		{logger.DefaultRequestLoggingFormat, fmt.Sprintf("127.0.0.1 - - [%s] test-server GET - \"/foo/bar\" HTTP/1.1 \"\" 200 4 0.000\n", logger.FormatTimestamp(ts)), "/foo/bar", []string{}, true},
		{logger.DefaultRequestLoggingFormat, fmt.Sprintf("127.0.0.1 - - [%s] test-server GET - \"/foo/bar\" HTTP/1.1 \"\" 200 4 0.000\n", logger.FormatTimestamp(ts)), "/foo/bar", []string{"/ping"}, false},
		{logger.DefaultRequestLoggingFormat, "", "/foo/bar", []string{"/foo/bar"}, false},
		{logger.DefaultRequestLoggingFormat, "", "/ping", []string{}, true},
		{logger.DefaultRequestLoggingFormat, "", "/ping", []string{"/ping"}, false},
		{logger.DefaultRequestLoggingFormat, "", "/ping", []string{"/ping"}, true},
		{logger.DefaultRequestLoggingFormat, "", "/ping", []string{"/foo/bar", "/ping"}, false},
		{"{{.RequestMethod}}", "GET\n", "/foo/bar", []string{}, true},
		{"{{.RequestMethod}}", "GET\n", "/foo/bar", []string{"/ping"}, false},
		{"{{.RequestMethod}}", "GET\n", "/ping", []string{}, false},
		{"{{.RequestMethod}}", "", "/ping", []string{"/ping"}, true},
	}

	for _, test := range tests {
		buf := bytes.NewBuffer(nil)
		handler := func(w http.ResponseWriter, req *http.Request) {
			_, ok := w.(http.Hijacker)
			if !ok {
				t.Error("http.Hijacker is not available")
			}

			w.Write([]byte("test"))
		}

		logger.SetOutput(buf)
		logger.SetReqTemplate(test.Format)
		if test.SilencePingLogging {
			test.ExcludePaths = append(test.ExcludePaths, "/ping")
		}
		logger.SetExcludePaths(test.ExcludePaths)
		h := LoggingHandler(http.HandlerFunc(handler))

		r, _ := http.NewRequest("GET", test.Path, nil)
		r.RemoteAddr = "127.0.0.1"
		r.Host = "test-server"

		h.ServeHTTP(httptest.NewRecorder(), r)

		actual := buf.String()
		if !strings.Contains(actual, test.ExpectedLogMessage) {
			t.Errorf("Log message was\n%s\ninstead of matching \n%s", actual, test.ExpectedLogMessage)
		}
	}
}
