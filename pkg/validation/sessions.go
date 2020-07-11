package validation

import (
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
)

func validateSessionCookieMinimal(o *options.Options) []string {
	if !o.Session.Cookie.Minimal {
		return []string{}
	}

	msgs := []string{}
	if o.PassAuthorization {
		msgs = append(msgs,
			"pass_authorization_header requires oauth tokens in sessions. session_cookie_minimal cannot be set")
	}
	if o.SetAuthorization {
		msgs = append(msgs,
			"set_authorization_header requires oauth tokens in sessions. session_cookie_minimal cannot be set")
	}
	if o.PassAccessToken {
		msgs = append(msgs,
			"pass_access_token requires oauth tokens in sessions. session_cookie_minimal cannot be set")
	}
	if o.Cookie.Refresh != time.Duration(0) {
		msgs = append(msgs,
			"cookie_refresh > 0 requires oauth tokens in sessions. session_cookie_minimal cannot be set")
	}
	return msgs
}
