package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoggingHandler_ServeHTTP(t *testing.T) {
	ts := time.Now()

	tests := []struct {
		Format,
		ExpectedLogMessage string
	}{
		{defaultRequestLoggingFormat, fmt.Sprintf("127.0.0.1 - - [%s] test-server GET - \"/foo/bar\" HTTP/1.1 \"\" 200 4 0.000\n", ts.Format("02/Jan/2006:15:04:05 -0700"))},
		{"{{.RequestMethod}}", "GET\n"},
	}

	for _, test := range tests {
		buf := bytes.NewBuffer(nil)
		handler := func(w http.ResponseWriter, req *http.Request) {
			w.Write([]byte("test"))
		}

		h := LoggingHandler(buf, http.HandlerFunc(handler), true, test.Format)

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
