package logger

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"
	"time"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
)

const injectedUserAgent = "agent\" injected\n\x1b[31m"

func newTestRequest(t *testing.T, userAgent string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", "/foo?bar=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "127.0.0.1"
	req.Header.Set("User-Agent", userAgent)
	return middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})
}

func TestPrintReqQuoting(t *testing.T) {
	tests := []struct {
		name      string
		format    string
		userAgent string
		expected  string
	}{
		{
			name:      "values are not quoted",
			format:    "{{.RequestURI}} {{.UserAgent}}",
			userAgent: "test-agent/1.0",
			expected:  "/foo?bar=1 test-agent/1.0\n",
		},
		{
			name:      "the format can quote them",
			format:    `"{{.RequestURI}}" "{{.UserAgent}}"`,
			userAgent: "test-agent/1.0",
			expected:  "\"/foo?bar=1\" \"test-agent/1.0\"\n",
		},
		{
			name:      "client input stays escaped",
			format:    "{{.UserAgent}}",
			userAgent: injectedUserAgent,
			expected:  `agent\" injected\n\x1b[31m` + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			l := New(0)
			l.writer = buf
			l.SetReqTemplate(tt.format)

			req := newTestRequest(t, tt.userAgent)
			l.PrintReq("user", "upstream", req, url.URL{Path: "/foo", RawQuery: "bar=1"}, time.Now(), 200, 4)

			if got := buf.String(); got != tt.expected {
				t.Errorf("got %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestPrintAuthfUserAgent(t *testing.T) {
	buf := &bytes.Buffer{}
	l := New(0)
	l.writer = buf
	l.SetAuthTemplate("{{.Status}} {{.UserAgent}}")

	l.PrintAuthf("user", newTestRequest(t, injectedUserAgent), AuthSuccess, "authenticated")

	expected := `AuthSuccess agent\" injected\n\x1b[31m` + "\n"
	if got := buf.String(); got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}
