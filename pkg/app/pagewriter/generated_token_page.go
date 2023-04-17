package pagewriter

import (
	// Import embed to allow importing default logo
	_ "embed"

	"html/template"
	"net/http"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// generatedTokenPageWriter is used to render sign-in pages.
type generatedTokenPageWriter struct {
	// Template is the sign-in page HTML template.
	template *template.Template

	// errorPageWriter is used to render an error if there are problems with rendering the sign-in page.
	errorPageWriter *errorPageWriter

	// Footer is the footer to be displayed at the bottom of the page.
	// If not set, a default footer will be used.
	footer string

	// Version is the OAuth2 Proxy version to be used in the default footer.
	version string

	// LogoData is the logo to render in the template.
	// This should contain valid html.
	logoData string
}

// WriteGeneratedTokenPage writes the sign-in page to the given response writer.
// It uses the redirectURL to be able to set the final destination for the user post login.
func (s *generatedTokenPageWriter) WriteGeneratedTokenPage(rw http.ResponseWriter, req *http.Request, token string) {
	// We allow unescaped template.HTML since it is user configured options
	/* #nosec G203 */
	t := struct {
		Version  string
		Footer   template.HTML
		LogoData template.HTML
		Token    string
	}{
		Version:  s.version,
		Footer:   template.HTML(s.footer),
		LogoData: template.HTML(s.logoData),
		Token:    token,
	}

	err := s.template.Execute(rw, t)
	if err != nil {
		logger.Printf("Error rendering sign-in template: %v", err)
		scope := middlewareapi.GetRequestScope(req)
		s.errorPageWriter.WriteErrorPage(rw, ErrorPageOpts{
			Status:    http.StatusInternalServerError,
			RequestID: scope.RequestID,
			AppError:  err.Error(),
		})
	}
}
