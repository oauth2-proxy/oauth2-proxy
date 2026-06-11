package logger

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sync"
	"text/template"
	"time"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	requestutil "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests/util"
)

// AuthStatus defines the different types of auth logging that occur
type AuthStatus string

// Level indicates the log level for legacy logger callers.
type Level int

const (
	// DefaultStandardLoggingFormat defines the default standard log format.
	DefaultStandardLoggingFormat = "[{{.Timestamp}}] [{{.File}}] {{.Message}}"
	// DefaultAuthLoggingFormat defines the default auth log format.
	DefaultAuthLoggingFormat = "{{.Client}} - {{.RequestID}} - {{.Username}} [{{.Timestamp}}] [{{.Status}}] {{.Message}}"
	// DefaultRequestLoggingFormat defines the default request log format.
	DefaultRequestLoggingFormat = "{{.Client}} - {{.RequestID}} - {{.Username}} [{{.Timestamp}}] {{.Host}} {{.RequestMethod}} {{.Upstream}} {{.RequestURI}} {{.Protocol}} {{.UserAgent}} {{.StatusCode}} {{.ResponseSize}} {{.RequestDuration}}"

	// AuthSuccess indicates that an auth attempt has succeeded explicitly
	AuthSuccess AuthStatus = "AuthSuccess"
	// AuthFailure indicates that an auth attempt has failed explicitly
	AuthFailure AuthStatus = "AuthFailure"
	// AuthError indicates that an auth attempt has failed due to an error
	AuthError AuthStatus = "AuthError"
)

const (
	// Llongfile logs the full file name and line number: /a/b/c/d.go:23.
	Llongfile = 1 << 6
	// Lshortfile logs the final file name element and line number: d.go:23. It overrides Llongfile.
	Lshortfile = 1 << 7
	// LUTC logs UTC timestamps rather than local time.
	LUTC = 1 << 8
	// LstdFlags is the initial value for the logger flags.
	LstdFlags = Lshortfile
)

const (
	// DEFAULT is the default legacy log level, effectively info.
	DEFAULT Level = 10
	// ERROR is the legacy error log level.
	ERROR Level = 11
)

// These are the containers for all values that are available as variables in the logging formats.
// All values are pre-formatted strings so it is easy to use them in the format string.
type stdLogMessageData struct {
	Timestamp,
	File,
	Message string
}

type authLogMessageData struct {
	Client,
	Host,
	Protocol,
	RequestID,
	RequestMethod,
	Timestamp,
	UserAgent,
	Username,
	Status,
	Message string
}

type reqLogMessageData struct {
	Client,
	Host,
	Protocol,
	RequestID,
	RequestDuration,
	RequestMethod,
	RequestURI,
	ResponseSize,
	StatusCode,
	Timestamp,
	Upstream,
	UserAgent,
	Username string
}

// GetClientFunc returns the apparent "real client IP" as a string.
type GetClientFunc = func(r *http.Request) string

// exitFunc is the function called by Fatal. Override in tests.
var exitFunc = os.Exit

// Package-level state
var (
	mu              sync.RWMutex
	logLevel                  = new(slog.LevelVar)
	defaultLogger             = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel, AddSource: true}))
	writer          io.Writer = os.Stdout
	errWriter       io.Writer = os.Stderr
	logFormat                 = "text"
	errToInfo                 = false
	standardEnabled           = true
	localTime                 = true
	flags                     = LstdFlags
	stdLogTemplate            = template.Must(template.New("std-log").Parse(DefaultStandardLoggingFormat))
	authTemplate              = template.Must(template.New("auth-log").Parse(DefaultAuthLoggingFormat))
	reqTemplate               = template.Must(template.New("req-log").Parse(DefaultRequestLoggingFormat))

	getClientFunc GetClientFunc = func(r *http.Request) string { return r.RemoteAddr }
	excludePaths  map[string]struct{}
	authEnabled   = true
	reqEnabled    = true
)

func init() {
	logLevel.Set(slog.LevelInfo)
	defaultLogger = slog.New(newLevelSplitHandler(logFormat, writer, errWriter))
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

// SetStandardEnabled enables or disables standard runtime logging.
func SetStandardEnabled(e bool) {
	mu.Lock()
	defer mu.Unlock()
	standardEnabled = e
}

// SetStandardTemplate sets the template for standard text logging.
func SetStandardTemplate(t string) {
	mu.Lock()
	defer mu.Unlock()
	stdLogTemplate = template.Must(template.New("std-log").Parse(t))
}

// SetAuthTemplate sets the template for authentication text logging.
func SetAuthTemplate(t string) {
	mu.Lock()
	defer mu.Unlock()
	authTemplate = template.Must(template.New("auth-log").Parse(t))
}

// SetReqTemplate sets the template for request text logging.
func SetReqTemplate(t string) {
	mu.Lock()
	defer mu.Unlock()
	reqTemplate = template.Must(template.New("req-log").Parse(t))
}

// SetLocalTime controls whether template text logs use local time or UTC.
func SetLocalTime(e bool) {
	mu.Lock()
	defer mu.Unlock()
	localTime = e
	if e {
		flags &^= LUTC
	} else {
		flags |= LUTC
	}
}

// FormatTimestamp returns a formatted timestamp using the current text log time zone setting.
func FormatTimestamp(ts time.Time) string {
	mu.RLock()
	useLocalTime := localTime
	mu.RUnlock()

	if !useLocalTime {
		ts = ts.UTC()
	}

	return ts.Format("2006/01/02 15:04:05")
}

// Flags returns the output flags for the standard logger.
func Flags() int {
	mu.RLock()
	defer mu.RUnlock()
	return flags
}

// SetFlags sets the output flags for the standard logger.
func SetFlags(flag int) {
	mu.Lock()
	defer mu.Unlock()
	flags = flag
	localTime = flag&LUTC == 0
}

// ---------- Structured log functions ----------

// Debug logs a message at Debug level with optional structured key-value pairs.
func Debug(msg string, args ...any) {
	if isTextFormat() {
		logStandardText(slog.LevelDebug, 3, msg, args...)
		return
	}

	defaultLogger.Debug(msg, args...)
}

// Debugf logs a formatted message at Debug level.
func Debugf(format string, args ...any) {
	if isTextFormat() {
		logStandardText(slog.LevelDebug, 3, fmt.Sprintf(format, args...))
		return
	}

	defaultLogger.Debug(fmt.Sprintf(format, args...))
}

// Info logs a message at Info level with optional structured key-value pairs.
func Info(msg string, args ...any) {
	if isTextFormat() {
		logStandardText(slog.LevelInfo, 3, msg, args...)
		return
	}

	defaultLogger.Info(msg, args...)
}

// Infof logs a formatted message at Info level.
func Infof(format string, args ...any) {
	if isTextFormat() {
		logStandardText(slog.LevelInfo, 3, fmt.Sprintf(format, args...))
		return
	}

	defaultLogger.Info(fmt.Sprintf(format, args...))
}

// Warn logs a message at Warn level with optional structured key-value pairs.
func Warn(msg string, args ...any) {
	if isTextFormat() {
		logStandardText(slog.LevelWarn, 3, msg, args...)
		return
	}

	defaultLogger.Warn(msg, args...)
}

// Warnf logs a formatted message at Warn level.
func Warnf(format string, args ...any) {
	if isTextFormat() {
		logStandardText(slog.LevelWarn, 3, fmt.Sprintf(format, args...))
		return
	}

	defaultLogger.Warn(fmt.Sprintf(format, args...))
}

// ErrMsg logs a message at Error level with optional structured key-value pairs.
func ErrMsg(msg string, args ...any) {
	if isTextFormat() {
		logStandardText(slog.LevelError, 3, msg, args...)
		return
	}

	defaultLogger.Error(msg, args...)
}

// ErrMsgf logs a formatted message at Error level.
func ErrMsgf(format string, args ...any) {
	if isTextFormat() {
		logStandardText(slog.LevelError, 3, fmt.Sprintf(format, args...))
		return
	}

	defaultLogger.Error(fmt.Sprintf(format, args...))
}

// FatalMsg logs a message at Error level and then calls os.Exit(1).
func FatalMsg(msg string, args ...any) {
	if isTextFormat() {
		logStandardText(slog.LevelError, 3, msg, args...)
		exitFunc(1)
		return
	}

	defaultLogger.Error(msg, args...)
	exitFunc(1)
}

// FatalMsgf logs a formatted message at Error level and then calls os.Exit(1).
func FatalMsgf(format string, args ...any) {
	if isTextFormat() {
		logStandardText(slog.LevelError, 3, fmt.Sprintf(format, args...))
		exitFunc(1)
		return
	}

	defaultLogger.Error(fmt.Sprintf(format, args...))
	exitFunc(1)
}

// PanicMsg logs a message at Error level and then panics.
func PanicMsg(msg string, args ...any) {
	if isTextFormat() {
		logStandardText(slog.LevelError, 3, msg, args...)
		panic(msg)
	}

	defaultLogger.Error(msg, args...)
	panic(msg)
}

// PanicMsgf logs a formatted message at Error level and then panics.
func PanicMsgf(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	if isTextFormat() {
		logStandardText(slog.LevelError, 3, s)
		panic(s)
	}

	defaultLogger.Error(s)
	panic(s)
}

func isTextFormat() bool {
	mu.RLock()
	defer mu.RUnlock()
	return logFormat == "text"
}

func logStandardText(level slog.Level, callerDepth int, msg string, args ...any) {
	if level < logLevel.Level() {
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if !standardEnabled {
		return
	}

	target := writer
	if level >= slog.LevelWarn && !errToInfo {
		target = errWriter
	}

	var logBuff bytes.Buffer
	err := stdLogTemplate.Execute(&logBuff, stdLogMessageData{
		Timestamp: formatTimestamp(time.Now(), localTime),
		File:      sourceFileFromCaller(callerDepth, flags),
		Message:   messageWithAttrs(msg, args...),
	})
	if err != nil {
		panic(err)
	}

	if _, err = logBuff.Write([]byte("\n")); err != nil {
		panic(err)
	}

	if _, err = target.Write(logBuff.Bytes()); err != nil {
		panic(err)
	}
}

func formatTimestamp(ts time.Time, useLocalTime bool) string {
	if !useLocalTime {
		ts = ts.UTC()
	}

	return ts.Format("2006/01/02 15:04:05")
}

func messageWithAttrs(msg string, args ...any) string {
	if len(args) == 0 {
		return msg
	}

	var buf bytes.Buffer
	buf.WriteString(msg)
	for i := 0; i < len(args); i += 2 {
		buf.WriteByte(' ')
		if i+1 >= len(args) {
			fmt.Fprint(&buf, args[i])
			continue
		}
		fmt.Fprint(&buf, args[i])
		buf.WriteByte('=')
		fmt.Fprint(&buf, args[i+1])
	}
	return buf.String()
}

func logAuthText(username string, req *http.Request, status AuthStatus, msg string, args ...any) {
	if username == "" {
		username = "-"
	}

	mu.Lock()
	defer mu.Unlock()

	scope := middlewareapi.GetRequestScope(req)
	err := authTemplate.Execute(writer, authLogMessageData{
		Client:        getClientFunc(req),
		Host:          requestutil.GetRequestHost(req),
		Protocol:      req.Proto,
		RequestID:     scope.RequestID,
		RequestMethod: req.Method,
		Timestamp:     formatTimestamp(time.Now(), localTime),
		UserAgent:     fmt.Sprintf("%q", req.UserAgent()),
		Username:      username,
		Status:        string(status),
		Message:       messageWithAttrs(msg, args...),
	})
	if err != nil {
		panic(err)
	}

	if _, err = writer.Write([]byte("\n")); err != nil {
		panic(err)
	}
}

func logRequestText(username, upstream string, req *http.Request, reqURL url.URL, ts time.Time, status int, size int) {
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

	duration := float64(time.Since(ts)) / float64(time.Second)

	mu.Lock()
	defer mu.Unlock()

	scope := middlewareapi.GetRequestScope(req)
	err := reqTemplate.Execute(writer, reqLogMessageData{
		Client:          getClientFunc(req),
		Host:            requestutil.GetRequestHost(req),
		Protocol:        req.Proto,
		RequestID:       scope.RequestID,
		RequestDuration: fmt.Sprintf("%0.3f", duration),
		RequestMethod:   req.Method,
		RequestURI:      fmt.Sprintf("%q", reqURL.RequestURI()),
		ResponseSize:    fmt.Sprintf("%d", size),
		StatusCode:      fmt.Sprintf("%d", status),
		Timestamp:       formatTimestamp(ts, localTime),
		Upstream:        upstream,
		UserAgent:       fmt.Sprintf("%q", req.UserAgent()),
		Username:        username,
	})
	if err != nil {
		panic(err)
	}

	if _, err = writer.Write([]byte("\n")); err != nil {
		panic(err)
	}
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
	format := logFormat
	mu.RUnlock()

	if !enabled {
		return
	}

	if username == "" {
		username = "-"
	}

	client := clientFunc(req)
	scope := middlewareapi.GetRequestScope(req)

	attrs := make([]any, 0, 16+len(args))
	attrs = append(attrs,
		"user", username,
		"client", client,
		"host", requestutil.GetRequestHost(req),
		"method", req.Method,
		"protocol", req.Proto,
		"user_agent", req.UserAgent(),
		"request_id", scope.RequestID,
		"status", string(status),
	)
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

	if level < logLevel.Level() {
		return
	}

	if format == "text" {
		logAuthText(username, req, status, msg, args...)
		return
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
	format := logFormat
	mu.RUnlock()

	if !enabled {
		return
	}

	if slog.LevelInfo < logLevel.Level() {
		return
	}

	if _, ok := excluded[reqURL.Path]; ok {
		return
	}

	if format == "text" {
		logRequestText(username, upstream, req, reqURL, ts, status, size)
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
		stdH = newTemplateTextHandler(w)
		errH = newTemplateTextHandler(errW)
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

type templateTextHandler struct {
	writer io.Writer
	attrs  []slog.Attr
}

func newTemplateTextHandler(w io.Writer) *templateTextHandler {
	return &templateTextHandler{writer: w}
}

func (h *templateTextHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= logLevel.Level()
}

func (h *templateTextHandler) Handle(_ context.Context, r slog.Record) error {
	mu.Lock()
	defer mu.Unlock()

	if !standardEnabled {
		return nil
	}

	var args []any
	for _, attr := range h.attrs {
		args = append(args, attr.Key, attr.Value.Any())
	}
	r.Attrs(func(attr slog.Attr) bool {
		args = append(args, attr.Key, attr.Value.Any())
		return true
	})

	var logBuff bytes.Buffer
	err := stdLogTemplate.Execute(&logBuff, stdLogMessageData{
		Timestamp: formatTimestamp(r.Time, localTime),
		File:      sourceFile(r.PC, flags),
		Message:   messageWithAttrs(r.Message, args...),
	})
	if err != nil {
		return err
	}

	if _, err = logBuff.Write([]byte("\n")); err != nil {
		return err
	}

	_, err = h.writer.Write(logBuff.Bytes())
	return err
}

func (h *templateTextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := &templateTextHandler{writer: h.writer}
	next.attrs = append(next.attrs, h.attrs...)
	next.attrs = append(next.attrs, attrs...)
	return next
}

func (h *templateTextHandler) WithGroup(_ string) slog.Handler {
	return h
}

func sourceFile(pc uintptr, flag int) string {
	if pc == 0 {
		return "???:0"
	}

	frame, _ := runtime.CallersFrames([]uintptr{pc}).Next()
	return formatFileLine(frame.File, frame.Line, flag)
}

func sourceFileFromCaller(depth int, flag int) string {
	_, file, line, ok := runtime.Caller(depth)
	if !ok {
		return "???:0"
	}

	return formatFileLine(file, line, flag)
}

func formatFileLine(file string, line int, flag int) string {
	if flag&Lshortfile != 0 {
		file = shortFile(file)
	}

	return fmt.Sprintf("%s:%d", file, line)
}

func shortFile(file string) string {
	for i := len(file) - 1; i > 0; i-- {
		if file[i] == '/' {
			return file[i+1:]
		}
	}

	return file
}
