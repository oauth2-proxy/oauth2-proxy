package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestLoggingHandler_ServeHTTP(t *testing.T) {
	tests := []struct {
		ExpectedLogMessage string
	}{
		{"GET"},
	}

	for _, test := range tests {
		tmpfile, _ := ioutil.TempFile("", "testfile")
		defer os.Remove(tmpfile.Name())
		handler := func(w http.ResponseWriter, req *http.Request) {
			w.Write([]byte("test"))
		}

		h := LoggingHandler(http.HandlerFunc(handler), true, tmpfile.Name())

		r, _ := http.NewRequest("GET", "/foo/bar", nil)
		r.RemoteAddr = "127.0.0.1"
		r.Host = "test-server"

		h.ServeHTTP(httptest.NewRecorder(), r)

		buf, _ := ioutil.ReadFile(tmpfile.Name())
		actual := string(buf)
		if !strings.Contains(actual, test.ExpectedLogMessage) {
			t.Errorf("Log message was\n%s\ninstead of expected \n%s", actual, test.ExpectedLogMessage)
		}
	}
}
