package options

import (
	"github.com/spf13/pflag"
)

type CSRFToken struct {
	CSRFToken bool `flag:"csrftoken" cfg:"csrftoken"`
}

func csrfTokenFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("csrftoken", pflag.ExitOnError)

	flagSet.Bool("csrftoken", false, "enable the CSRF token generation")
	return flagSet
}

func CSRFTokenDefaults() CSRFToken {
	return CSRFToken{
		CSRFToken: false,
	}
}
