package app

import (
	"html/template"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// ErrorPage is used to render error pages.
type ErrorPage struct {
	// Template is the error page HTML template.
	Template *template.Template

	// ProxyPrefix is the prefix under which OAuth2 Proxy pages are served.
	ProxyPrefix string

	// Footer is the footer to be displayed at the bottom of the page.
	// If not set, a default footer will be used.
	Footer string

	// Version is the OAuth2 Proxy version to be used in the default footer.
	Version string
}

// Render writes an error page to the given response writer.
// It uses the passed redirectURL to give users the option to go back to where
// they originally came from or try signing in again.
func (e *ErrorPage) Render(rw http.ResponseWriter, status int, redirectURL string, appError string) {
	rw.WriteHeader(status)

	// We allow unescaped template.HTML since it is user configured options
	/* #nosec G203 */
	data := struct {
		Title       string
		Message     string
		ProxyPrefix string
		StatusCode  int
		Redirect    string
		Footer      template.HTML
		Version     string
	}{
		Title:       http.StatusText(status),
		Message:     appError,
		ProxyPrefix: e.ProxyPrefix,
		StatusCode:  status,
		Redirect:    redirectURL,
		Footer:      template.HTML(e.Footer),
		Version:     e.Version,
	}

	if err := e.Template.Execute(rw, data); err != nil {
		logger.Printf("Error rendering error template: %v", err)
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

// ProxyErrorHandler is used by the upstream ReverseProxy to render error pages
// when there are issues with upstream servers.
// It is expected to always render a bad gateway error.
func (e *ErrorPage) ProxyErrorHandler(rw http.ResponseWriter, req *http.Request, proxyErr error) {
	logger.Errorf("Error proxying to upstream server: %v", proxyErr)
	e.Render(rw, http.StatusBadGateway, "", "Error proxying to upstream server")
}
