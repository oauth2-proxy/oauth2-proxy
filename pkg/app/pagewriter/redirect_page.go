package pagewriter

import (
	"html/template"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// redirectPageWriter is used to render redirect pages.
type redirectPageWriter struct {
	// template is the redirect page HTML template.
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

// RedirectPageOpts bundles up all the content needed to write the Redirect Page
type RedirectPageOpts struct {
	// Redirect URL for "Redirect" and "Sign in" buttons
	RedirectURL string
}

// WriteRedirectPage writes an redirect page to the given response writer.
// It uses the passed redirectURL to give users the option to go back to where
// they originally came from or try signing in again.
func (e *redirectPageWriter) WriteRedirectPage(rw http.ResponseWriter, opts RedirectPageOpts) {
	rw.WriteHeader(http.StatusOK)

	// We allow unescaped template.HTML since it is user configured options
	/* #nosec G203 */
	data := struct {
		ProxyPrefix string
		Redirect    string
		Footer      template.HTML
		Version     string
	}{
		ProxyPrefix: e.proxyPrefix,
		Redirect:    opts.RedirectURL,
		Footer:      template.HTML(e.footer),
		Version:     e.version,
	}

	if err := e.template.Execute(rw, data); err != nil {
		logger.Printf("Error rendering redirect template: %v", err)
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}
