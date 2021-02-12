package app

import (
	"html/template"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// signInPageWriter is used to render sign-in pages.
type signInPageWriter struct {
	// Template is the sign-in page HTML template.
	template *template.Template

	// errorPageWriter is used to render an error if there are problems with rendering the sign-in page.
	errorPageWriter *errorPageWriter

	// ProxyPrefix is the prefix under which OAuth2 Proxy pages are served.
	proxyPrefix string

	// ProviderName is the name of the provider that should be displayed on the login button.
	providerName string

	// SignInMessage is the messge displayed above the login button.
	signInMessage string

	// Footer is the footer to be displayed at the bottom of the page.
	// If not set, a default footer will be used.
	footer string

	// Version is the OAuth2 Proxy version to be used in the default footer.
	version string

	// DisplayLoginForm determines whether or not the basic auth password form is displayed on the sign-in page.
	displayLoginForm bool
}

// WriteSignInPage writes the sign-in page to the given response writer.
// It uses the redirectURL to be able to set the final destination for the user post login.
func (s *signInPageWriter) WriteSignInPage(rw http.ResponseWriter, redirectURL string) {
	// We allow unescaped template.HTML since it is user configured options
	/* #nosec G203 */
	t := struct {
		ProviderName  string
		SignInMessage template.HTML
		CustomLogin   bool
		Redirect      string
		Version       string
		ProxyPrefix   string
		Footer        template.HTML
	}{
		ProviderName:  s.providerName,
		SignInMessage: template.HTML(s.signInMessage),
		CustomLogin:   s.displayLoginForm,
		Redirect:      redirectURL,
		Version:       s.version,
		ProxyPrefix:   s.proxyPrefix,
		Footer:        template.HTML(s.footer),
	}

	err := s.template.Execute(rw, t)
	if err != nil {
		logger.Printf("Error rendering sign-in template: %v", err)
		s.errorPageWriter.WriteErrorPage(rw, http.StatusInternalServerError, redirectURL, err.Error())
	}
}
