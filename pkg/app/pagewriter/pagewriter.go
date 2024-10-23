package pagewriter

import (
	"fmt"
	"net/http"
)

// Writer is an interface for rendering html templates for both sign-in and
// error pages.
// It can also be used to write errors for the http.ReverseProxy used in the
// upstream package.
type Writer interface {
	WriteSignInPage(rw http.ResponseWriter, req *http.Request, redirectURL string, statusCode int)
	WriteErrorPage(rw http.ResponseWriter, opts ErrorPageOpts)
	ProxyErrorHandler(rw http.ResponseWriter, req *http.Request, proxyErr error)
	WriteRobotsTxt(rw http.ResponseWriter, req *http.Request)
}

// pageWriter implements the Writer interface
type pageWriter struct {
	*errorPageWriter
	*signInPageWriter
	*staticPageWriter
}

// Opts contains all options required to configure the template
// rendering within OAuth2 Proxy.
type Opts struct {
	// TemplatesPath is the path from which to load custom templates for the sign-in and error pages.
	TemplatesPath string

	// ProxyPrefix is the prefix under which OAuth2 Proxy pages are served.
	ProxyPrefix string

	// Footer is the footer to be displayed at the bottom of the page.
	// If not set, a default footer will be used.
	Footer string

	// Version is the OAuth2 Proxy version to be used in the default footer.
	Version string

	// Debug determines whether errors pages should be rendered with detailed
	// errors.
	Debug bool

	// DisplayLoginForm determines whether or not the basic auth password form is displayed on the sign-in page.
	DisplayLoginForm bool

	// ProviderName is the name of the provider that should be displayed on the login button.
	ProviderName string

	// SignInMessage is the messge displayed above the login button.
	SignInMessage string

	// CustomLogo is the path or URL to a logo to be displayed on the sign in page.
	// The logo can be either PNG, JPG/JPEG or SVG.
	// If a URL is used, image support depends on the browser.
	CustomLogo string
}

// NewWriter constructs a Writer from the options given to allow
// rendering of sign-in and error pages.
func NewWriter(opts Opts) (Writer, error) {
	templates, err := loadTemplates(opts.TemplatesPath)
	if err != nil {
		return nil, fmt.Errorf("error loading templates: %v", err)
	}

	logoData, err := loadCustomLogo(opts.CustomLogo)
	if err != nil {
		return nil, fmt.Errorf("error loading logo: %v", err)
	}

	errorPage := &errorPageWriter{
		template:    templates.Lookup("error.html"),
		proxyPrefix: opts.ProxyPrefix,
		footer:      opts.Footer,
		version:     opts.Version,
		debug:       opts.Debug,
	}

	signInPage := &signInPageWriter{
		template:         templates.Lookup("sign_in.html"),
		errorPageWriter:  errorPage,
		proxyPrefix:      opts.ProxyPrefix,
		providerName:     opts.ProviderName,
		signInMessage:    opts.SignInMessage,
		footer:           opts.Footer,
		version:          opts.Version,
		displayLoginForm: opts.DisplayLoginForm,
		logoData:         logoData,
	}

	staticPages, err := newStaticPageWriter(opts.TemplatesPath, errorPage)
	if err != nil {
		return nil, fmt.Errorf("error loading static page writer: %v", err)
	}

	return &pageWriter{
		errorPageWriter:  errorPage,
		signInPageWriter: signInPage,
		staticPageWriter: staticPages,
	}, nil
}

// WriterFuncs is an implementation of the PageWriter interface based
// on override functions.
// If any of the funcs are not provided, a default implementation will be used.
// This is primarily for us in testing.
type WriterFuncs struct {
	SignInPageFunc func(rw http.ResponseWriter, req *http.Request, redirectURL string, statusCode int)
	ErrorPageFunc  func(rw http.ResponseWriter, opts ErrorPageOpts)
	ProxyErrorFunc func(rw http.ResponseWriter, req *http.Request, proxyErr error)
	RobotsTxtfunc  func(rw http.ResponseWriter, req *http.Request)
}

// WriteSignInPage implements the Writer interface.
// If the SignInPageFunc is provided, this will be used, else a default
// implementation will be used.
func (w *WriterFuncs) WriteSignInPage(rw http.ResponseWriter, req *http.Request, redirectURL string, statusCode int) {
	if w.SignInPageFunc != nil {
		w.SignInPageFunc(rw, req, redirectURL, statusCode)
		return
	}

	if _, err := rw.Write([]byte("Sign In")); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
	}
}

// WriteErrorPage implements the Writer interface.
// If the ErrorPageFunc is provided, this will be used, else a default
// implementation will be used.
func (w *WriterFuncs) WriteErrorPage(rw http.ResponseWriter, opts ErrorPageOpts) {
	if w.ErrorPageFunc != nil {
		w.ErrorPageFunc(rw, opts)
		return
	}

	rw.WriteHeader(opts.Status)
	errMsg := fmt.Sprintf("%d - %v", opts.Status, opts.AppError)
	if _, err := rw.Write([]byte(errMsg)); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
	}
}

// ProxyErrorHandler implements the Writer interface.
// If the ProxyErrorFunc is provided, this will be used, else a default
// implementation will be used.
func (w *WriterFuncs) ProxyErrorHandler(rw http.ResponseWriter, req *http.Request, proxyErr error) {
	if w.ProxyErrorFunc != nil {
		w.ProxyErrorFunc(rw, req, proxyErr)
		return
	}

	w.WriteErrorPage(rw, ErrorPageOpts{
		Status:   http.StatusBadGateway,
		AppError: proxyErr.Error(),
	})
}

// WriteRobotsTxt implements the Writer interface.
// If the RobotsTxtfunc is provided, this will be used, else a default
// implementation will be used.
func (w *WriterFuncs) WriteRobotsTxt(rw http.ResponseWriter, req *http.Request) {
	if w.RobotsTxtfunc != nil {
		w.RobotsTxtfunc(rw, req)
		return
	}

	if _, err := rw.Write([]byte("Allow: *")); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
	}
}
