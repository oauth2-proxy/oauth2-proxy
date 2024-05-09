package options

// Templates includes options for configuring the sign in and error pages
// appearance.
type PageTemplates struct {
	// Path is the path to a folder containing a sign_in.html and an error.html
	// template.
	// These files will be used instead of the default templates if present.
	// If either file is missing, the default will be used instead.
	Path string `json:"path,omitempty"`

	// CustomLogo is the path or a URL to a logo that should replace the default logo
	// on the sign_in page template.
	// Supported formats are .svg, .png, .jpg and .jpeg.
	// If URL is used the format support depends on the browser.
	// To disable the default logo, set this value to "-".
	CustomLogo string `json:"customLogo,omitempty"`

	// Banner overides the default sign_in page banner text. If unspecified,
	// the message will give users a list of allowed email domains.
	Banner string `json:"banner,omitempty"`

	// Footer overrides the default sign_in page footer text.
	Footer string `json:"footer,omitempty"`

	// DisplayLoginForm determines whether the sign_in page should render a
	// password form if a static passwords file (htpasswd file) has been
	// configured.
	DisplayLoginForm bool `json:"displayLoginForm"`

	// Debug renders detailed errors when an error page is shown.
	// It is not advised to use this in production as errors may contain sensitive
	// information.
	// Use only for diagnosing backend errors.
	Debug bool `json:"debug,omitempty"`
}

// templatesDefaults creates a Templates and populates it with any default values
func pageTemplatesDefaults() PageTemplates {
	return PageTemplates{
		Path:             "",
		CustomLogo:       "",
		Banner:           "",
		Footer:           "",
		DisplayLoginForm: true,
		Debug:            false,
	}
}
