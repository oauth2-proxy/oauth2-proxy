package logger

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sync"
	"text/template"
	"time"
)

type AuthStatus string

const (
	// Default logging formats
	DefaultStandardLoggingFormat = "[{{.Timestamp}}] [{{.File}}] {{.Message}}"
	DefaultAuthLoggingFormat     = "{{.Client}} - {{.Username}} [{{.Timestamp}}] [{{.Status}}] {{.Message}}"
	DefaultRequestLoggingFormat  = "{{.Client}} - {{.Username}} [{{.Timestamp}}] {{.Host}} {{.RequestMethod}} {{.Upstream}} {{.RequestURI}} {{.Protocol}} {{.UserAgent}} {{.StatusCode}} {{.ResponseSize}} {{.RequestDuration}}"

	// Auth statuses
	AuthSuccess AuthStatus = "AuthSuccess"
	AuthFailure AuthStatus = "AuthFailure"
	AuthError   AuthStatus = "AuthError"

	// General logging config
	Llongfile               = 1 << iota // full file name and line number: /a/b/c/d.go:23
	Lshortfile                          // final file name element and line number: d.go:23. overrides Llongfile
	LUTC                                // use UTC rather than the local time zone
	LstdFlags  = Lshortfile             // initial values for the standard logger
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

type Logger struct {
	mu             sync.Mutex
	flag           int
	writer         io.Writer
	stdEnabled     bool
	authEnabled    bool
	reqEnabled     bool
	stdLogTemplate *template.Template
	authTemplate   *template.Template
	reqTemplate    *template.Template
}

// New creates a new Standarderr Logger.
func New(flag int) *Logger {
	return &Logger{
		writer:         os.Stderr,
		flag:           flag,
		stdEnabled:     true,
		authEnabled:    true,
		reqEnabled:     true,
		stdLogTemplate: template.Must(template.New("std-log").Parse(DefaultStandardLoggingFormat)),
		authTemplate:   template.Must(template.New("auth-log").Parse(DefaultAuthLoggingFormat)),
		reqTemplate:    template.Must(template.New("req-log").Parse(DefaultRequestLoggingFormat)),
	}
}

var std = New(LstdFlags)

// Cheap integer to fixed-width decimal ASCII. Give a negative width to avoid zero-padding.
func itoa(buf *[]byte, i int, wid int) {
	// Assemble decimal in reverse order.
	var b [20]byte
	bp := len(b) - 1
	for i >= 10 || wid > 1 {
		wid--
		q := i / 10
		b[bp] = byte('0' + i - q*10)
		bp--
		i = q
	}
	// i < 10
	b[bp] = byte('0' + i)
	*buf = append(*buf, b[bp:]...)
}

// Output a standard log template with a simple message.
// Write a final newline at the end of every message.
func (l *Logger) Output(calldepth int, message string) {
	if !l.stdEnabled {
		return
	}

	now := time.Now()
	file := "???:0"

	if l.flag&(Lshortfile|Llongfile) != 0 {
		file = l.GetFileLineString(calldepth + 1)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.stdLogTemplate.Execute(l.writer, stdLogMessageData{
		Timestamp: FormatTimestamp(now),
		File:      file,
		Message:   message,
	})

	l.writer.Write([]byte("\n"))
}

// Print auth details to the logger. Requires an http.Request to log details.
// Remaining arguments are handled in the manner of fmt.Sprintf.
// Writes a final newline to the end of every message.
func (l *Logger) PrintAuth(username string, req *http.Request, status AuthStatus, format string, a ...interface{}) {
	if !l.authEnabled {
		return
	}

	now := time.Now()

	if username == "" {
		username = "-"
	}

	client := GetClient(req)

	l.mu.Lock()
	defer l.mu.Unlock()

	l.authTemplate.Execute(l.writer, authLogMessageData{
		Client:        client,
		Host:          req.Host,
		Protocol:      req.Proto,
		RequestMethod: req.Method,
		Timestamp:     FormatTimestamp(now),
		UserAgent:     fmt.Sprintf("%q", req.UserAgent()),
		Username:      username,
		Status:        fmt.Sprintf("%s", status),
		Message:       fmt.Sprintf(format, a...),
	})

	l.writer.Write([]byte("\n"))
}

// Print HTTP request details to the Logger.
// Writes a final newline to the end of every message.
func (l *Logger) PrintReq(username, upstream string, req *http.Request, url url.URL, ts time.Time, status int, size int) {
	if !l.reqEnabled {
		return
	}

	duration := float64(time.Now().Sub(ts)) / float64(time.Second)

	if username == "" {
		username = "-"
	}

	if upstream == "" {
		upstream = "-"
	}

	if url.User != nil && username == "-" {
		if name := url.User.Username(); name != "" {
			username = name
		}
	}

	client := GetClient(req)

	l.mu.Lock()
	defer l.mu.Unlock()

	l.reqTemplate.Execute(l.writer, reqLogMessageData{
		Client:          client,
		Host:            req.Host,
		Protocol:        req.Proto,
		RequestDuration: fmt.Sprintf("%0.3f", duration),
		RequestMethod:   req.Method,
		RequestURI:      fmt.Sprintf("%q", url.RequestURI()),
		ResponseSize:    fmt.Sprintf("%d", size),
		StatusCode:      fmt.Sprintf("%d", status),
		Timestamp:       FormatTimestamp(ts),
		Upstream:        upstream,
		UserAgent:       fmt.Sprintf("%q", req.UserAgent()),
		Username:        username,
	})

	l.writer.Write([]byte("\n"))
}

// Obtains file and line number info for the standard output log
func (l *Logger) GetFileLineString(calldepth int) string {
	var file string
	var line int
	var ok bool

	_, file, line, ok = runtime.Caller(calldepth)
	if !ok {
		file = "???"
		line = 0
	}

	if l.flag&Lshortfile != 0 {
		short := file
		for i := len(file) - 1; i > 0; i-- {
			if file[i] == '/' {
				short = file[i+1:]
				break
			}
		}
		file = short
	}

	return fmt.Sprintf("%s:%d", file, line)
}

// Parse an HTTP request for the client/remote IP
func GetClient(req *http.Request) string {
	client := req.Header.Get("X-Real-IP")
	if client == "" {
		client = req.RemoteAddr
	}

	if c, _, err := net.SplitHostPort(client); err == nil {
		client = c
	}

	return client
}

// Returns a formatted timestamp
func (l *Logger) FormatTimestamp(ts time.Time) string {
	if l.flag&LUTC != 0 {
		ts = ts.UTC()
	}

	return ts.Format("2006/01/02 15:04:05")
}

// Flags returns the output flags for the logger.
func (l *Logger) Flags() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.flag
}

// SetFlags sets the output flags for the logger.
func (l *Logger) SetFlags(flag int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.flag = flag
}

// Set all logging enabled for the logger.
func (l *Logger) SetStandardEnabled(e bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stdEnabled = e
}

// Set auth logging enabled for the standard logger
func (l *Logger) SetAuthEnabled(e bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.authEnabled = e
}

// Set request logging enabled for the standard logger
func (l *Logger) SetReqEnabled(e bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqEnabled = e
}

// Set the output template for the standard logger
func (l *Logger) SetStandardTemplate(t string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stdLogTemplate = template.Must(template.New("std-log").Parse(t))
}

// Set the auth template for the standard logger
func (l *Logger) SetAuthTemplate(t string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.authTemplate = template.Must(template.New("auth-log").Parse(t))
}

// Set the request template for the standard logger
func (l *Logger) SetReqTemplate(t string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqTemplate = template.Must(template.New("req-log").Parse(t))
}

// These functions utilize the standard logger.

// Returns a formatted timestamp for the standard logger.
func FormatTimestamp(ts time.Time) string {
	return std.FormatTimestamp(ts)
}

// Flags returns the output flags for the standard logger.
func Flags() int {
	return std.Flags()
}

// SetFlags sets the output flags for the standard logger.
func SetFlags(flag int) {
	std.SetFlags(flag)
}

// SetOutput sets the output destination for the standard logger.
func SetOutput(w io.Writer) {
	std.mu.Lock()
	defer std.mu.Unlock()
	std.writer = w
}

// Set output logging enabled for the standard logger
func SetStandardEnabled(e bool) {
	std.SetStandardEnabled(e)
}

// Set auth logging enabled for the standard logger
func SetAuthEnabled(e bool) {
	std.SetAuthEnabled(e)
}

// Set request logging enabled for the standard logger
func SetReqEnabled(e bool) {
	std.SetReqEnabled(e)
}

// Set the output template for the standard logger
func SetStandardTemplate(t string) {
	std.SetStandardTemplate(t)
}

// Set the auth template for the standard logger
func SetAuthTemplate(t string) {
	std.SetAuthTemplate(t)
}

// Set the request template for the standard logger
func SetReqTemplate(t string) {
	std.SetReqTemplate(t)
}

// Print calls Output to print to the standard logger.
// Arguments are handled in the manner of fmt.Print.
func Print(v ...interface{}) {
	std.Output(2, fmt.Sprint(v...))
}

// Printf calls Output to print to the standard logger.
// Arguments are handled in the manner of fmt.Printf.
func Printf(format string, v ...interface{}) {
	std.Output(2, fmt.Sprintf(format, v...))
}

// Println calls Output to print to the standard logger.
// Arguments are handled in the manner of fmt.Println.
func Println(v ...interface{}) {
	std.Output(2, fmt.Sprintln(v...))
}

// Fatal is equivalent to Print() followed by a call to os.Exit(1).
func Fatal(v ...interface{}) {
	std.Output(2, fmt.Sprint(v...))
	os.Exit(1)
}

// Fatalf is equivalent to Printf() followed by a call to os.Exit(1).
func Fatalf(format string, v ...interface{}) {
	std.Output(2, fmt.Sprintf(format, v...))
	os.Exit(1)
}

// Fatalln is equivalent to Println() followed by a call to os.Exit(1).
func Fatalln(v ...interface{}) {
	std.Output(2, fmt.Sprintln(v...))
	os.Exit(1)
}

// Panic is equivalent to Print() followed by a call to panic().
func Panic(v ...interface{}) {
	s := fmt.Sprint(v...)
	std.Output(2, s)
	panic(s)
}

// Panicf is equivalent to Printf() followed by a call to panic().
func Panicf(format string, v ...interface{}) {
	s := fmt.Sprintf(format, v...)
	std.Output(2, s)
	panic(s)
}

// Panicln is equivalent to Println() followed by a call to panic().
func Panicln(v ...interface{}) {
	s := fmt.Sprintln(v...)
	std.Output(2, s)
	panic(s)
}

// PrintAuthf writes authentication details to the standard logger.
// Arguments are handled in the manner of fmt.Printf.
func PrintAuthf(username string, req *http.Request, status AuthStatus, format string, a ...interface{}) {
	std.PrintAuth(username, req, status, format, a...)
}

// PrintAuthf writes request details to the standard logger.
func PrintReq(username, upstream string, req *http.Request, url url.URL, ts time.Time, status int, size int) {
	std.PrintReq(username, upstream, req, url, ts, status, size)
}
