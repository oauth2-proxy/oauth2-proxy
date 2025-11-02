package pagewriter

import (
	// Import embed to allow importing default logo
	_ "embed"

	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"html/template"
	"net/http"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

//go:embed default_logo.svg
var defaultLogoData string

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

	// LogoData is the logo to render in the template.
	// This should contain valid html.
	logoData string
}

// WriteSignInPage writes the sign-in page to the given response writer.
// It uses the redirectURL to be able to set the final destination for the user post login.
func (s *signInPageWriter) WriteSignInPage(rw http.ResponseWriter, req *http.Request, redirectURL string, statusCode int) {
	t := struct {
		ProviderName  string
		SignInMessage template.HTML
		StatusCode    int
		CustomLogin   bool
		Redirect      string
		Version       string
		ProxyPrefix   string
		Footer        template.HTML
		LogoData      template.HTML
	}{
		ProviderName:  s.providerName,
		SignInMessage: template.HTML(s.signInMessage), // #nosec G203 -- We allow unescaped template.HTML since it is user configured options
		StatusCode:    statusCode,
		CustomLogin:   s.displayLoginForm,
		Redirect:      redirectURL,
		Version:       s.version,
		ProxyPrefix:   s.proxyPrefix,
		Footer:        template.HTML(s.footer),   // #nosec G203 -- We allow unescaped template.HTML since it is user configured options
		LogoData:      template.HTML(s.logoData), // #nosec G203 -- We allow unescaped template.HTML since it is user configured options
	}

	err := s.template.Execute(rw, t)
	if err != nil {
		logger.Printf("Error rendering sign-in template: %v", err)
		scope := middlewareapi.GetRequestScope(req)
		s.errorPageWriter.WriteErrorPage(rw, ErrorPageOpts{
			Status:      http.StatusInternalServerError,
			RedirectURL: redirectURL,
			RequestID:   scope.RequestID,
			AppError:    err.Error(),
		})
	}
}

// loadCustomLogo loads the logo file from the path and encodes it to an HTML
// entity or if a URL is provided then it's used directly,
// otherwise if no custom logo is provided, the OAuth2 Proxy Icon is used instead.
func loadCustomLogo(logoPath string) (string, error) {
	if logoPath == "" {
		// The default logo is an SVG so this will be valid to just return.
		return defaultLogoData, nil
	}

	if logoPath == "-" {
		// Return no logo when the custom logo is set to `-`.
		// This disables the logo rendering.
		return "", nil
	}

	if strings.HasPrefix(logoPath, "https://") {
		// Return img tag pointing to the URL.
		return fmt.Sprintf("<img src=\"%s\" alt=\"Logo\" />", logoPath), nil
	}

	logoData, err := os.ReadFile(logoPath)
	if err != nil {
		return "", fmt.Errorf("could not read logo file: %v", err)
	}

	extension := strings.ToLower(filepath.Ext(logoPath))
	switch extension {
	case ".svg":
		return string(logoData), nil
	case ".jpg", ".jpeg":
		return encodeImg(logoData, "jpeg"), nil
	case ".png":
		return encodeImg(logoData, "png"), nil
	default:
		return "", fmt.Errorf("unknown extension: %q, supported extensions are .svg, .jpg, .jpeg and .png", extension)
	}
}

// encodeImg takes the raw image data and converts it to an HTML Img tag with
// a base64 data source.
func encodeImg(data []byte, format string) string {
	b64Data := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("<img src=\"data:image/%s;base64,%s\" alt=\"Logo\" />", format, b64Data)
}
