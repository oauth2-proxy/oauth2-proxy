package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	requestutil "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests/util"
)

// AuthStatus defines the different types of auth logging that occur
type AuthStatus string

const (
	// AuthSuccess indicates that an auth attempt has succeeded explicitly
	AuthSuccess AuthStatus = "AuthSuccess"
	// AuthFailure indicates that an auth attempt has failed explicitly
	AuthFailure AuthStatus = "AuthFailure"
	// AuthError indicates that an auth attempt has failed due to an error
	AuthError AuthStatus = "AuthError"
)

// GetClientFunc returns the apparent "real client IP" as a string.
type GetClientFunc = func(r *http.Request) string

// exitFunc is the function called by Fatal. Override in tests.
var exitFunc = os.Exit

// Package-level state
var (
	mu            sync.RWMutex
	logLevel                = new(slog.LevelVar)
	defaultLogger           = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel, AddSource: true}))
	writer        io.Writer = os.Stdout
	errWriter     io.Writer = os.Stderr
	logFormat     string    = "json"
	errToInfo     bool      = false

	getClientFunc GetClientFunc = func(r *http.Request) string { return r.RemoteAddr }
	excludePaths  map[string]struct{}
	authEnabled   = true
	reqEnabled    = true
)

func init() {
	logLevel.Set(slog.LevelInfo)
	slog.SetDefault(defaultLogger)
}

// Setup initializes the logger with the given level, format, and writers.
// format must be "json" or "text".
func Setup(level slog.Level, format string, w io.Writer, errW io.Writer) {
	mu.Lock()
	defer mu.Unlock()

	logLevel.Set(level)
	writer = w
	errWriter = errW
	logFormat = format

	handler := newLevelSplitHandler(format, w, errW)
	defaultLogger = slog.New(handler)
	slog.SetDefault(defaultLogger)
}

// SetLevel changes the log level at runtime.
func SetLevel(level slog.Level) {
	mu.Lock()
	defer mu.Unlock()
	logLevel.Set(level)
}

// GetLevel returns the current log level.
func GetLevel() slog.Level {
	mu.RLock()
	defer mu.RUnlock()
	return logLevel.Level()
}

// SetOutput changes the standard output writer and reconfigures the handler.
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	writer = w
	if errToInfo {
		errWriter = w
	}
	handler := newLevelSplitHandler(logFormat, writer, errWriter)
	defaultLogger = slog.New(handler)
	slog.SetDefault(defaultLogger)
}

// SetErrOutput changes the error output writer and reconfigures the handler.
func SetErrOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	errWriter = w
	handler := newLevelSplitHandler(logFormat, writer, errWriter)
	defaultLogger = slog.New(handler)
	slog.SetDefault(defaultLogger)
}

// SetErrToInfo routes error-level logs to the standard writer instead of the error writer.
func SetErrToInfo(e bool) {
	mu.Lock()
	defer mu.Unlock()
	errToInfo = e
	ew := errWriter
	if e {
		ew = writer
	}
	handler := newLevelSplitHandler(logFormat, writer, ew)
	defaultLogger = slog.New(handler)
	slog.SetDefault(defaultLogger)
}

// SetGetClientFunc sets the function which determines the apparent "real client IP".
func SetGetClientFunc(f GetClientFunc) {
	mu.Lock()
	defer mu.Unlock()
	getClientFunc = f
}

// SetExcludePaths sets the paths to exclude from request logging.
func SetExcludePaths(s []string) {
	mu.Lock()
	defer mu.Unlock()
	excludePaths = make(map[string]struct{})
	for _, p := range s {
		excludePaths[p] = struct{}{}
	}
}

// SetAuthEnabled enables or disables auth logging.
func SetAuthEnabled(e bool) {
	mu.Lock()
	defer mu.Unlock()
	authEnabled = e
}

// SetReqEnabled enables or disables request logging.
func SetReqEnabled(e bool) {
	mu.Lock()
	defer mu.Unlock()
	reqEnabled = e
}

// ---------- Structured log functions ----------

// Debug logs a message at Debug level with optional structured key-value pairs.
func Debug(msg string, args ...any) {
	defaultLogger.Debug(msg, args...)
}

// Debugf logs a formatted message at Debug level.
func Debugf(format string, args ...any) {
	defaultLogger.Debug(fmt.Sprintf(format, args...))
}

// Info logs a message at Info level with optional structured key-value pairs.
func Info(msg string, args ...any) {
	defaultLogger.Info(msg, args...)
}

// Infof logs a formatted message at Info level.
func Infof(format string, args ...any) {
	defaultLogger.Info(fmt.Sprintf(format, args...))
}

// Warn logs a message at Warn level with optional structured key-value pairs.
func Warn(msg string, args ...any) {
	defaultLogger.Warn(msg, args...)
}

// Warnf logs a formatted message at Warn level.
func Warnf(format string, args ...any) {
	defaultLogger.Warn(fmt.Sprintf(format, args...))
}

// ErrMsg logs a message at Error level with optional structured key-value pairs.
func ErrMsg(msg string, args ...any) {
	defaultLogger.Error(msg, args...)
}

// ErrMsgf logs a formatted message at Error level.
func ErrMsgf(format string, args ...any) {
	defaultLogger.Error(fmt.Sprintf(format, args...))
}

// FatalMsg logs a message at Error level and then calls os.Exit(1).
func FatalMsg(msg string, args ...any) {
	defaultLogger.Error(msg, args...)
	exitFunc(1)
}

// FatalMsgf logs a formatted message at Error level and then calls os.Exit(1).
func FatalMsgf(format string, args ...any) {
	defaultLogger.Error(fmt.Sprintf(format, args...))
	exitFunc(1)
}

// PanicMsg logs a message at Error level and then panics.
func PanicMsg(msg string, args ...any) {
	defaultLogger.Error(msg, args...)
	panic(msg)
}

// PanicMsgf logs a formatted message at Error level and then panics.
func PanicMsgf(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	defaultLogger.Error(s)
	panic(s)
}

// ---------- Structured auth and request logging ----------

// LogAuth logs an authentication event with structured attributes.
// The log level is derived from the AuthStatus:
//   - AuthSuccess → Info
//   - AuthFailure → Warn
//   - AuthError → Error
func LogAuth(username string, req *http.Request, status AuthStatus, msg string, args ...any) {
	mu.RLock()
	enabled := authEnabled
	clientFunc := getClientFunc
	mu.RUnlock()

	if !enabled {
		return
	}

	if username == "" {
		username = "-"
	}

	client := clientFunc(req)
	scope := middlewareapi.GetRequestScope(req)

	attrs := []any{
		"user", username,
		"client", client,
		"host", requestutil.GetRequestHost(req),
		"method", req.Method,
		"protocol", req.Proto,
		"user_agent", req.UserAgent(),
		"request_id", scope.RequestID,
		"status", string(status),
	}
	attrs = append(attrs, args...)

	var level slog.Level
	switch status {
	case AuthSuccess:
		level = slog.LevelInfo
	case AuthFailure:
		level = slog.LevelWarn
	case AuthError:
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	defaultLogger.Log(context.Background(), level, msg, attrs...)
}

// LogRequest logs an HTTP request with structured attributes at Info level.
// It respects excludePaths and the reqEnabled flag.
func LogRequest(username, upstream string, req *http.Request, reqURL url.URL, ts time.Time, status int, size int) {
	mu.RLock()
	enabled := reqEnabled
	excluded := excludePaths
	clientFunc := getClientFunc
	mu.RUnlock()

	if !enabled {
		return
	}

	if _, ok := excluded[reqURL.Path]; ok {
		return
	}

	duration := float64(time.Since(ts)) / float64(time.Second)

	if username == "" {
		username = "-"
	}

	if upstream == "" {
		upstream = "-"
	}

	if reqURL.User != nil && username == "-" {
		if name := reqURL.User.Username(); name != "" {
			username = name
		}
	}

	client := clientFunc(req)
	scope := middlewareapi.GetRequestScope(req)

	defaultLogger.Info("request",
		"user", username,
		"client", client,
		"host", requestutil.GetRequestHost(req),
		"method", req.Method,
		"uri", reqURL.RequestURI(),
		"protocol", req.Proto,
		"upstream", upstream,
		"user_agent", req.UserAgent(),
		"status_code", status,
		"response_size", size,
		"duration_s", fmt.Sprintf("%0.3f", duration),
		"request_id", scope.RequestID,
	)
}

// ---------- Deprecated functions (backward compatibility) ----------
// These will be removed after all call sites are migrated.

// Deprecated: Use Info instead.
func Print(v ...interface{}) {
	defaultLogger.Info(fmt.Sprint(v...))
}

// Deprecated: Use Info or Infof instead.
func Printf(format string, v ...interface{}) {
	defaultLogger.Info(fmt.Sprintf(format, v...))
}

// Deprecated: Use Info instead.
func Println(v ...interface{}) {
	defaultLogger.Info(fmt.Sprint(v...))
}

// Deprecated: Use ErrMsg instead.
func Error(v ...interface{}) {
	defaultLogger.Error(fmt.Sprint(v...))
}

// Deprecated: Use ErrMsgf instead.
func Errorf(format string, v ...interface{}) {
	defaultLogger.Error(fmt.Sprintf(format, v...))
}

// Deprecated: Use ErrMsg instead.
func Errorln(v ...interface{}) {
	defaultLogger.Error(fmt.Sprint(v...))
}

// Deprecated: Use FatalMsg instead.
func Fatal(v ...interface{}) {
	defaultLogger.Error(fmt.Sprint(v...))
	exitFunc(1)
}

// Deprecated: Use FatalMsgf instead.
func Fatalf(format string, v ...interface{}) {
	defaultLogger.Error(fmt.Sprintf(format, v...))
	exitFunc(1)
}

// Deprecated: Use FatalMsg instead.
func Fatalln(v ...interface{}) {
	defaultLogger.Error(fmt.Sprint(v...))
	exitFunc(1)
}

// Deprecated: Use PanicMsg instead.
func Panic(v ...interface{}) {
	s := fmt.Sprint(v...)
	defaultLogger.Error(s)
	panic(s)
}

// Deprecated: Use PanicMsgf instead.
func Panicf(format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)
	defaultLogger.Error(s)
	panic(s)
}

// Deprecated: Use PanicMsg instead.
func Panicln(v ...interface{}) {
	s := fmt.Sprint(v...)
	defaultLogger.Error(s)
	panic(s)
}

// Deprecated: Use LogAuth instead.
func PrintAuthf(username string, req *http.Request, status AuthStatus, format string, a ...interface{}) {
	LogAuth(username, req, status, fmt.Sprintf(format, a...))
}

// Deprecated: Use LogRequest instead.
func PrintReq(username, upstream string, req *http.Request, url url.URL, ts time.Time, status int, size int) {
	LogRequest(username, upstream, req, url, ts, status, size)
}

// Deprecated: No longer needed — slog handles source location via AddSource.
func SetFlags(_ int) {}

// Deprecated: No longer needed.
func Flags() int { return 0 }

// Deprecated: Controlled by log level now.
func SetStandardEnabled(_ bool) {}

// Deprecated: No longer needed — use Setup with appropriate format.
func SetStandardTemplate(_ string) {}

// Deprecated: No longer needed — use Setup with appropriate format.
func SetAuthTemplate(_ string) {}

// Deprecated: No longer needed — use Setup with appropriate format.
func SetReqTemplate(_ string) {}

// Deprecated: No longer needed.
func FormatTimestamp(ts time.Time) string {
	return ts.Format("2006/01/02 15:04:05")
}

// ---------- Level-split handler ----------

// levelSplitHandler routes log records to different writers based on level.
// Records at Warn level and above go to the error handler.
// Records below Warn go to the standard handler.
type levelSplitHandler struct {
	stdHandler slog.Handler
	errHandler slog.Handler
}

func newLevelSplitHandler(format string, w io.Writer, errW io.Writer) *levelSplitHandler {
	opts := &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: true,
	}
	errOpts := &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: true,
	}

	var stdH, errH slog.Handler
	switch format {
	case "text":
		stdH = slog.NewTextHandler(w, opts)
		errH = slog.NewTextHandler(errW, errOpts)
	default: // "json"
		stdH = slog.NewJSONHandler(w, opts)
		errH = slog.NewJSONHandler(errW, errOpts)
	}

	return &levelSplitHandler{
		stdHandler: stdH,
		errHandler: errH,
	}
}

func (h *levelSplitHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= logLevel.Level()
}

func (h *levelSplitHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		return h.errHandler.Handle(ctx, r)
	}
	return h.stdHandler.Handle(ctx, r)
}

func (h *levelSplitHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &levelSplitHandler{
		stdHandler: h.stdHandler.WithAttrs(attrs),
		errHandler: h.errHandler.WithAttrs(attrs),
	}
}

func (h *levelSplitHandler) WithGroup(name string) slog.Handler {
	return &levelSplitHandler{
		stdHandler: h.stdHandler.WithGroup(name),
		errHandler: h.errHandler.WithGroup(name),
	}
}
