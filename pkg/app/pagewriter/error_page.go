package pagewriter

import (
	"fmt"
	"html/template"
	"net/http"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// errorMessages are default error messages for each of the different
// http status codes expected to be rendered in the error page.
var errorMessages = map[int]string{
	http.StatusInternalServerError: "Oops! Something went wrong. For more information contact your server administrator.",
	http.StatusNotFound:            "We could not find the resource you were looking for.",
	http.StatusForbidden:           "You do not have permission to access this resource.",
	http.StatusUnauthorized:        "You need to be logged in to access this resource.",
}

// errorPageWriter is used to render error pages.
type errorPageWriter struct {
	// template is the error page HTML template.
	template *template.Template

	// proxyPrefix is the prefix under which OAuth2 Proxy pages are served.
	proxyPrefix string

	// footer is the footer to be displayed at the bottom of the page.
	// If not set, a default footer will be used.
	footer string

	// version is the OAuth2 Proxy version to be used in the default footer.
	version string

	// debug determines whether errors pages should be rendered with detailed
	// errors.
	debug bool
}

// ErrorPageOpts bundles up all the content needed to write the Error Page
type ErrorPageOpts struct {
	// HTTP status code
	Status int
	// Redirect URL for "Go back" and "Sign in" buttons
	RedirectURL string
	// The UUID of the request
	RequestID string
	// App Error shown in debug mode
	AppError string
	// Generic error messages shown in non-debug mode
	Messages []interface{}
}

// WriteErrorPage writes an error page to the given response writer.
// It uses the passed redirectURL to give users the option to go back to where
// they originally came from or try signing in again.
func (e *errorPageWriter) WriteErrorPage(rw http.ResponseWriter, opts ErrorPageOpts) {
	rw.WriteHeader(opts.Status)

	data := struct {
		Title       string
		Message     string
		ProxyPrefix string
		StatusCode  int
		Redirect    string
		RequestID   string
		Footer      template.HTML
		Version     string
	}{
		Title:       http.StatusText(opts.Status),
		Message:     e.getMessage(opts.Status, opts.AppError, opts.Messages...),
		ProxyPrefix: e.proxyPrefix,
		StatusCode:  opts.Status,
		Redirect:    opts.RedirectURL,
		RequestID:   opts.RequestID,
		Footer:      template.HTML(e.footer), // #nosec G203 -- We allow unescaped template.HTML since it is user configured options
		Version:     e.version,
	}

	if err := e.template.Execute(rw, data); err != nil {
		logger.Printf("Error rendering error template: %v", err)
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// ProxyErrorHandler is used by the upstream ReverseProxy to render error pages
// when there are issues with upstream servers.
// It is expected to always render a bad gateway error.
func (e *errorPageWriter) ProxyErrorHandler(rw http.ResponseWriter, req *http.Request, proxyErr error) {
	logger.Errorf("Error proxying to upstream server: %v", proxyErr)
	scope := middlewareapi.GetRequestScope(req)
	e.WriteErrorPage(rw, ErrorPageOpts{
		Status:      http.StatusBadGateway,
		RedirectURL: "", // The user is already logged in and has hit an upstream error. Makes no sense to redirect in this case.
		RequestID:   scope.RequestID,
		AppError:    proxyErr.Error(),
		Messages:    []interface{}{"There was a problem connecting to the upstream server."},
	})
}

// getMessage creates the message for the template parameters.
// If the errorPagewriter.Debug is enabled, the application error takes precedence.
// Otherwise, any messages will be used.
// The first message is expected to be a format string.
// If no messages are supplied, a default error message will be used.
func (e *errorPageWriter) getMessage(status int, appError string, messages ...interface{}) string {
	if e.debug {
		return appError
	}
	if len(messages) > 0 {
		format := fmt.Sprintf("%v", messages[0])
		return fmt.Sprintf(format, messages[1:]...)
	}
	if msg, ok := errorMessages[status]; ok {
		return msg
	}
	return "Unknown error"
}
