package options

import "github.com/spf13/pflag"

// Templates includes options for configuring the sign in and error pages
// appearance.
type Templates struct {
	// Path is the path to a folder containing a sign_in.html and an error.html
	// template.
	// These files will be used instead of the default templates if present.
	// If either file is missing, the default will be used instead.
	Path string `flag:"custom-templates-dir" cfg:"custom_templates_dir"`

	// CustomLogo is the path to a logo that should replace the default logo
	// on the sign_in page template.
	// Supported formats are .svg, .png, .jpg and .jpeg.
	// To disable the default logo, set this value to "-".
	CustomLogo string `flag:"custom-sign-in-logo" cfg:"custom_sign_in_logo"`

	// Banner overides the default sign_in page banner text. If unspecified,
	// the message will give users a list of allowed email domains.
	Banner string `flag:"banner" cfg:"banner"`

	// Footer overrides the default sign_in page footer text.
	Footer string `flag:"footer" cfg:"footer"`

	// DisplayLoginForm determines whether the sign_in page should render a
	// password form if a static passwords file (htpasswd file) has been
	// configured.
	DisplayLoginForm bool `flag:"display-htpasswd-form" cfg:"display_htpasswd_form"`

	// Debug renders detailed errors when an error page is shown.
	// It is not advised to use this in production as errors may contain sensitive
	// information.
	// Use only for diagnosing backend errors.
	Debug bool `flag:"show-debug-on-error" cfg:"show-debug-on-error"`
}

func templatesFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("templates", pflag.ExitOnError)

	flagSet.String("custom-templates-dir", "", "path to custom html templates")
	flagSet.String("custom-sign-in-logo", "", "path to an custom image for the sign_in page logo. Use \"-\" to disable default logo.")
	flagSet.String("banner", "", "custom banner string. Use \"-\" to disable default banner.")
	flagSet.String("footer", "", "custom footer string. Use \"-\" to disable default footer.")
	flagSet.Bool("display-htpasswd-form", true, "display username / password login form if an htpasswd file is provided")
	flagSet.Bool("show-debug-on-error", false, "show detailed error information on error pages (WARNING: this may contain sensitive information - do not use in production)")

	return flagSet
}

// templatesDefaults creates a Templates and populates it with any default values
func templatesDefaults() Templates {
	return Templates{
		DisplayLoginForm: true,
	}
}
