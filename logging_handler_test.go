package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pusher/oauth2_proxy/logger"
)

func TestLoggingHandler_ServeHTTP(t *testing.T) {
	ts := time.Now()

	tests := []struct {
		Format,
		ExpectedLogMessage string
	}{
		{logger.DefaultRequestLoggingFormat, fmt.Sprintf("127.0.0.1 - - [%s] test-server GET - \"/foo/bar\" HTTP/1.1 \"\" 200 4 0.000\n", logger.FormatTimestamp(ts))},
		{"{{.RequestMethod}}", "GET\n"},
	}

	for _, test := range tests {
		buf := bytes.NewBuffer(nil)
		handler := func(w http.ResponseWriter, req *http.Request) {
			w.Write([]byte("test"))
		}

		logger.SetOutput(buf)
		logger.SetReqTemplate(test.Format)
		h := LoggingHandler(http.HandlerFunc(handler))

		r, _ := http.NewRequest("GET", "/foo/bar", nil)
		r.RemoteAddr = "127.0.0.1"
		r.Host = "test-server"

		h.ServeHTTP(httptest.NewRecorder(), r)

		actual := buf.String()
		if actual != test.ExpectedLogMessage {
			t.Errorf("Log message was\n%s\ninstead of expected \n%s", actual, test.ExpectedLogMessage)
		}
	}
}
