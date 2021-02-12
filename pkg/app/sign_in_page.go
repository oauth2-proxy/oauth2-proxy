package app

import (
	"html/template"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// SignInPage is used to render sign-in pages.
type SignInPage struct {
	// Template is the sign-in page HTML template.
	Template *template.Template

	// ErrorPage is used to render an error if there are problems with rendering the sign-in page.
	ErrorPage *ErrorPage

	// ProxyPrefix is the prefix under which OAuth2 Proxy pages are served.
	ProxyPrefix string

	// ProviderName is the name of the provider that should be displayed on the login button.
	ProviderName string

	// SignInMessage is the messge displayed above the login button.
	SignInMessage string

	// Footer is the footer to be displayed at the bottom of the page.
	// If not set, a default footer will be used.
	Footer string

	// Version is the OAuth2 Proxy version to be used in the default footer.
	Version string

	// DisplayLoginForm determines whether or not the basic auth password form is displayed on the sign-in page.
	DisplayLoginForm bool
}

// Render writes the sign-in page to the given response writer.
// It uses the redirectURL to be able to set the final destination for the user post login.
func (s *SignInPage) Render(rw http.ResponseWriter, redirectURL string) {
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
		ProviderName:  s.ProviderName,
		SignInMessage: template.HTML(s.SignInMessage),
		CustomLogin:   s.DisplayLoginForm,
		Redirect:      redirectURL,
		Version:       s.Version,
		ProxyPrefix:   s.ProxyPrefix,
		Footer:        template.HTML(s.Footer),
	}

	err := s.Template.Execute(rw, t)
	if err != nil {
		logger.Printf("Error rendering sign-in template: %v", err)
		s.ErrorPage.Render(rw, http.StatusInternalServerError, redirectURL, err.Error())
	}
}
