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

	// Banner overides the default sign_in page banner text. If unspecified,
	// the message will give users a list of allowed email domains.
	Banner string `flag:"banner" cfg:"banner"`

	// Footer overrides the default sign_in page footer text.
	Footer string `flag:"footer" cfg:"footer"`

	// DisplayLoginForm determines whether the sign_in page should render a
	// password form if a static passwords file (htpasswd file) has been
	// configured.
	DisplayLoginForm bool `flag:"display-htpasswd-form" cfg:"display_htpasswd_form"`
}

func templatesFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("templates", pflag.ExitOnError)

	flagSet.String("custom-templates-dir", "", "path to custom html templates")
	flagSet.String("banner", "", "custom banner string. Use \"-\" to disable default banner.")
	flagSet.String("footer", "", "custom footer string. Use \"-\" to disable default footer.")
	flagSet.Bool("display-htpasswd-form", true, "display username / password login form if an htpasswd file is provided")

	return flagSet
}

// templatesDefaults creates a Templates and populates it with any default values
func templatesDefaults() Templates {
	return Templates{
		DisplayLoginForm: true,
	}
}
