package logger

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
)

// resetLogger resets the logger to defaults for test isolation.
func resetLogger(t *testing.T) {
	t.Helper()
	logLevel.Set(slog.LevelInfo)
	authEnabled = true
	reqEnabled = true
	excludePaths = nil
	getClientFunc = func(r *http.Request) string { return r.RemoteAddr }
	errToInfo = false
}

// parseJSON parses a JSON log line into a map.
func parseJSON(t *testing.T, data []byte) map[string]any {
	t.Helper()
	// Take only the first line if there are multiple
	line := strings.TrimSpace(strings.Split(string(data), "\n")[0])
	if line == "" {
		t.Fatal("empty log output")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("failed to parse JSON log: %v\nraw: %s", err, line)
	}
	return m
}

func TestSetup_JSONFormat(t *testing.T) {
	resetLogger(t)
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelInfo, "json", buf, errBuf)

	Info("hello", "key", "val")

	m := parseJSON(t, buf.Bytes())
	if m["msg"] != "hello" {
		t.Errorf("expected msg=hello, got %v", m["msg"])
	}
	if m["key"] != "val" {
		t.Errorf("expected key=val, got %v", m["key"])
	}
	if m["level"] != "INFO" {
		t.Errorf("expected level=INFO, got %v", m["level"])
	}
	if _, ok := m["time"]; !ok {
		t.Error("expected time field in JSON output")
	}
	if _, ok := m["source"]; !ok {
		t.Error("expected source field in JSON output")
	}
}

func TestSetup_TextFormat(t *testing.T) {
	resetLogger(t)
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelInfo, "text", buf, errBuf)

	Info("hello", "key", "val")

	out := buf.String()
	if !strings.Contains(out, "level=INFO") {
		t.Errorf("expected level=INFO in text output, got: %s", out)
	}
	if !strings.Contains(out, "msg=hello") {
		t.Errorf("expected msg=hello in text output, got: %s", out)
	}
	if !strings.Contains(out, "key=val") {
		t.Errorf("expected key=val in text output, got: %s", out)
	}
}

func TestLevelFiltering(t *testing.T) {
	resetLogger(t)
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelInfo, "json", buf, errBuf)

	Debug("should not appear")
	if buf.Len() > 0 {
		t.Error("Debug message should be filtered at Info level")
	}

	Info("should appear")
	if buf.Len() == 0 {
		t.Error("Info message should appear at Info level")
	}
	m := parseJSON(t, buf.Bytes())
	if m["msg"] != "should appear" {
		t.Errorf("expected msg='should appear', got %v", m["msg"])
	}

	// Error should go to errBuf
	ErrMsg("error msg")
	if errBuf.Len() == 0 {
		t.Error("Error message should appear in errBuf")
	}
}

func TestSetLevel_Runtime(t *testing.T) {
	resetLogger(t)
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelInfo, "json", buf, errBuf)

	Debug("hidden")
	if buf.Len() > 0 {
		t.Error("Debug should be hidden at Info level")
	}

	SetLevel(slog.LevelDebug)

	Debug("visible")
	if buf.Len() == 0 {
		t.Error("Debug should be visible after SetLevel(Debug)")
	}
	m := parseJSON(t, buf.Bytes())
	if m["msg"] != "visible" {
		t.Errorf("expected msg='visible', got %v", m["msg"])
	}
}

func TestLevelSplitHandler(t *testing.T) {
	resetLogger(t)
	stdBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelDebug, "json", stdBuf, errBuf)

	Info("info msg")
	if stdBuf.Len() == 0 {
		t.Error("Info should go to stdout")
	}
	if errBuf.Len() > 0 {
		t.Error("Info should NOT go to stderr")
	}

	stdBuf.Reset()

	Warn("warn msg")
	if errBuf.Len() == 0 {
		t.Error("Warn should go to stderr")
	}
	if stdBuf.Len() > 0 {
		t.Error("Warn should NOT go to stdout")
	}

	errBuf.Reset()

	ErrMsg("error msg")
	if errBuf.Len() == 0 {
		t.Error("Error should go to stderr")
	}
}

func TestErrToInfo(t *testing.T) {
	resetLogger(t)
	stdBuf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelInfo, "json", stdBuf, errBuf)

	SetErrToInfo(true)

	ErrMsg("goes to stdout")
	if stdBuf.Len() == 0 {
		t.Error("Error should go to stdout when ErrToInfo is true")
	}
	if errBuf.Len() > 0 {
		t.Error("Error should NOT go to stderr when ErrToInfo is true")
	}
}

func TestLogAuth_Success(t *testing.T) {
	resetLogger(t)
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelDebug, "json", buf, errBuf)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:1234"
	scope := &middlewareapi.RequestScope{RequestID: "test-request-id"}
	req = middlewareapi.AddRequestScope(req, scope)

	LogAuth("user@test.com", req, AuthSuccess, "authenticated via OAuth2")

	m := parseJSON(t, buf.Bytes())
	if m["level"] != "INFO" {
		t.Errorf("AuthSuccess should log at INFO, got %v", m["level"])
	}
	if m["user"] != "user@test.com" {
		t.Errorf("expected user=user@test.com, got %v", m["user"])
	}
	if m["status"] != "AuthSuccess" {
		t.Errorf("expected status=AuthSuccess, got %v", m["status"])
	}
	if m["request_id"] != "test-request-id" {
		t.Errorf("expected request_id=test-request-id, got %v", m["request_id"])
	}
	if m["msg"] != "authenticated via OAuth2" {
		t.Errorf("expected msg='authenticated via OAuth2', got %v", m["msg"])
	}
}

func TestLogAuth_Failure(t *testing.T) {
	resetLogger(t)
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelDebug, "json", buf, errBuf)

	req := httptest.NewRequest("GET", "/test", nil)
	scope := &middlewareapi.RequestScope{RequestID: "req-id"}
	req = middlewareapi.AddRequestScope(req, scope)

	LogAuth("bad-user", req, AuthFailure, "invalid credentials")

	// AuthFailure → Warn → goes to errBuf
	m := parseJSON(t, errBuf.Bytes())
	if m["level"] != "WARN" {
		t.Errorf("AuthFailure should log at WARN, got %v", m["level"])
	}
	if m["status"] != "AuthFailure" {
		t.Errorf("expected status=AuthFailure, got %v", m["status"])
	}
}

func TestLogAuth_Error(t *testing.T) {
	resetLogger(t)
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelDebug, "json", buf, errBuf)

	req := httptest.NewRequest("GET", "/test", nil)
	scope := &middlewareapi.RequestScope{RequestID: "req-id"}
	req = middlewareapi.AddRequestScope(req, scope)

	LogAuth("user", req, AuthError, "internal error")

	m := parseJSON(t, errBuf.Bytes())
	if m["level"] != "ERROR" {
		t.Errorf("AuthError should log at ERROR, got %v", m["level"])
	}
}

func TestLogAuth_Disabled(t *testing.T) {
	resetLogger(t)
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelDebug, "json", buf, errBuf)
	SetAuthEnabled(false)

	req := httptest.NewRequest("GET", "/test", nil)
	scope := &middlewareapi.RequestScope{RequestID: "req-id"}
	req = middlewareapi.AddRequestScope(req, scope)

	LogAuth("user", req, AuthSuccess, "should not appear")

	if buf.Len() > 0 || errBuf.Len() > 0 {
		t.Error("LogAuth should produce no output when auth logging is disabled")
	}
}

func TestLogRequest(t *testing.T) {
	resetLogger(t)
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelDebug, "json", buf, errBuf)

	req := httptest.NewRequest("GET", "/foo/bar", nil)
	req.RemoteAddr = "127.0.0.1:5678"
	scope := &middlewareapi.RequestScope{RequestID: "req-123"}
	req = middlewareapi.AddRequestScope(req, scope)

	reqURL := *req.URL
	LogRequest("testuser", "backend", req, reqURL, time.Now(), 200, 1024)

	// LogRequest uses time.Now() internally so we can't easily test duration_s exactly.
	// Just parse and check fields.
	m := parseJSON(t, buf.Bytes())
	if m["msg"] != "request" {
		t.Errorf("expected msg=request, got %v", m["msg"])
	}
	if m["level"] != "INFO" {
		t.Errorf("expected level=INFO, got %v", m["level"])
	}
	if m["user"] != "testuser" {
		t.Errorf("expected user=testuser, got %v", m["user"])
	}
	if m["upstream"] != "backend" {
		t.Errorf("expected upstream=backend, got %v", m["upstream"])
	}
	if m["method"] != "GET" {
		t.Errorf("expected method=GET, got %v", m["method"])
	}
	// status_code comes as float64 from JSON
	if sc, ok := m["status_code"].(float64); !ok || int(sc) != 200 {
		t.Errorf("expected status_code=200, got %v", m["status_code"])
	}
	if rs, ok := m["response_size"].(float64); !ok || int(rs) != 1024 {
		t.Errorf("expected response_size=1024, got %v", m["response_size"])
	}
	if _, ok := m["duration_s"]; !ok {
		t.Error("expected duration_s field")
	}
	if m["request_id"] != "req-123" {
		t.Errorf("expected request_id=req-123, got %v", m["request_id"])
	}
}

func TestLogRequest_ExcludePaths(t *testing.T) {
	resetLogger(t)
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelDebug, "json", buf, errBuf)
	SetExcludePaths([]string{"/healthz", "/ping"})

	req := httptest.NewRequest("GET", "/healthz", nil)
	scope := &middlewareapi.RequestScope{RequestID: "req-id"}
	req = middlewareapi.AddRequestScope(req, scope)

	reqURL := *req.URL
	LogRequest("user", "-", req, reqURL, time.Now(), 200, 0)

	if buf.Len() > 0 {
		t.Error("LogRequest should not log excluded paths")
	}
}

func TestLogRequest_Disabled(t *testing.T) {
	resetLogger(t)
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelDebug, "json", buf, errBuf)
	SetReqEnabled(false)

	req := httptest.NewRequest("GET", "/foo", nil)
	scope := &middlewareapi.RequestScope{RequestID: "req-id"}
	req = middlewareapi.AddRequestScope(req, scope)

	reqURL := *req.URL
	LogRequest("user", "-", req, reqURL, time.Now(), 200, 0)

	if buf.Len() > 0 {
		t.Error("LogRequest should produce no output when request logging is disabled")
	}
}

func TestFatal(t *testing.T) {
	resetLogger(t)
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelInfo, "json", buf, errBuf)

	// Override exitFunc to capture the exit code
	var exitCode int
	exitFunc = func(code int) { exitCode = code }
	defer func() { exitFunc = nil }() // will panic on real exit if not restored

	Fatal("fatal error")

	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	if errBuf.Len() == 0 {
		t.Error("Fatal should produce error-level output")
	}
	m := parseJSON(t, errBuf.Bytes())
	if m["level"] != "ERROR" {
		t.Errorf("expected level=ERROR, got %v", m["level"])
	}

	// Restore
	exitFunc = func(code int) {}
}

func TestDeprecatedPrintf(t *testing.T) {
	resetLogger(t)
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelInfo, "json", buf, errBuf)

	Printf("hello %s", "world")

	m := parseJSON(t, buf.Bytes())
	if m["msg"] != "hello world" {
		t.Errorf("expected msg='hello world', got %v", m["msg"])
	}
	if m["level"] != "INFO" {
		t.Errorf("expected level=INFO, got %v", m["level"])
	}
}

func TestDeprecatedErrorf(t *testing.T) {
	resetLogger(t)
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelInfo, "json", buf, errBuf)

	Errorf("error: %s", "something")

	m := parseJSON(t, errBuf.Bytes())
	if m["msg"] != "error: something" {
		t.Errorf("expected msg='error: something', got %v", m["msg"])
	}
	if m["level"] != "ERROR" {
		t.Errorf("expected level=ERROR, got %v", m["level"])
	}
}

func TestDeprecatedPrintAuthf(t *testing.T) {
	resetLogger(t)
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelDebug, "json", buf, errBuf)

	req := httptest.NewRequest("GET", "/test", nil)
	scope := &middlewareapi.RequestScope{RequestID: "req-id"}
	req = middlewareapi.AddRequestScope(req, scope)

	PrintAuthf("user@test.com", req, AuthSuccess, "authenticated via %s", "OAuth2")

	m := parseJSON(t, buf.Bytes())
	if m["msg"] != "authenticated via OAuth2" {
		t.Errorf("expected msg='authenticated via OAuth2', got %v", m["msg"])
	}
	if m["user"] != "user@test.com" {
		t.Errorf("expected user=user@test.com, got %v", m["user"])
	}
}

func TestSetOutput(t *testing.T) {
	resetLogger(t)
	buf1 := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	Setup(slog.LevelInfo, "json", buf1, errBuf)

	Info("before")
	if buf1.Len() == 0 {
		t.Error("expected output in buf1")
	}

	buf2 := &bytes.Buffer{}
	SetOutput(buf2)
	buf1.Reset()

	Info("after")
	if buf2.Len() == 0 {
		t.Error("expected output in buf2 after SetOutput")
	}
	if buf1.Len() > 0 {
		t.Error("buf1 should have no new output after SetOutput")
	}
}

func TestGetLevel(t *testing.T) {
	resetLogger(t)
	buf := &bytes.Buffer{}
	Setup(slog.LevelWarn, "json", buf, buf)

	if GetLevel() != slog.LevelWarn {
		t.Errorf("expected LevelWarn, got %v", GetLevel())
	}

	SetLevel(slog.LevelDebug)
	if GetLevel() != slog.LevelDebug {
		t.Errorf("expected LevelDebug, got %v", GetLevel())
	}
}
