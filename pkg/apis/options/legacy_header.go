package options

import "github.com/spf13/pflag"

type LegacyHeaders struct {
	PassBasicAuth     bool `flag:"pass-basic-auth" cfg:"pass_basic_auth"`
	PassAccessToken   bool `flag:"pass-access-token" cfg:"pass_access_token"`
	PassUserHeaders   bool `flag:"pass-user-headers" cfg:"pass_user_headers"`
	PassAuthorization bool `flag:"pass-authorization-header" cfg:"pass_authorization_header"`

	SetBasicAuth     bool `flag:"set-basic-auth" cfg:"set_basic_auth"`
	SetXAuthRequest  bool `flag:"set-xauthrequest" cfg:"set_xauthrequest"`
	SetAuthorization bool `flag:"set-authorization-header" cfg:"set_authorization_header"`

	PreferEmailToUser    bool   `flag:"prefer-email-to-user" cfg:"prefer_email_to_user"`
	BasicAuthPassword    string `flag:"basic-auth-password" cfg:"basic_auth_password"`
	SkipAuthStripHeaders bool   `flag:"skip-auth-strip-headers" cfg:"skip_auth_strip_headers"`
}

func legacyHeadersFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("headers", pflag.ExitOnError)

	flagSet.Bool("pass-basic-auth", true, "pass HTTP Basic Auth, X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.Bool("pass-access-token", false, "pass OAuth access_token to upstream via X-Forwarded-Access-Token header")
	flagSet.Bool("pass-user-headers", true, "pass X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.Bool("pass-authorization-header", false, "pass the Authorization Header to upstream")

	flagSet.Bool("set-basic-auth", false, "set HTTP Basic Auth information in response (useful in Nginx auth_request mode)")
	flagSet.Bool("set-xauthrequest", false, "set X-Auth-Request-User and X-Auth-Request-Email response headers (useful in Nginx auth_request mode)")
	flagSet.Bool("set-authorization-header", false, "set Authorization response headers (useful in Nginx auth_request mode)")

	flagSet.Bool("prefer-email-to-user", false, "Prefer to use the Email address as the Username when passing information to upstream. Will only use Username if Email is unavailable, eg. htaccess authentication. Used in conjunction with -pass-basic-auth and -pass-user-headers")
	flagSet.String("basic-auth-password", "", "the password to set when passing the HTTP Basic Auth header")
	flagSet.Bool("skip-auth-strip-headers", true, "strips X-Forwarded-* style authentication headers & Authorization header if they would be set by oauth2-proxy")

	return flagSet
}

// convert takes the legacy request/response headers and converts them to
// the new format for InjectRequestHeaders and InjectResponseHeaders
func (l *LegacyHeaders) convert() ([]Header, []Header) {
	return l.getRequestHeaders(), l.getResponseHeaders()
}

func (l *LegacyHeaders) getRequestHeaders() []Header {
	requestHeaders := []Header{}

	if l.PassBasicAuth && l.BasicAuthPassword != "" {
		requestHeaders = append(requestHeaders, getBasicAuthHeader(l.PreferEmailToUser, l.BasicAuthPassword))
	}

	// In the old implementation, PassUserHeaders is a subset of PassBasicAuth
	if l.PassBasicAuth || l.PassUserHeaders {
		requestHeaders = append(requestHeaders, getPassUserHeaders(l.PreferEmailToUser)...)
		requestHeaders = append(requestHeaders, getPreferredUsernameHeader())
	}

	if l.PassAccessToken {
		requestHeaders = append(requestHeaders, getPassAccessTokenHeader())
	}

	if l.PassAuthorization {
		requestHeaders = append(requestHeaders, getAuthorizationHeader())
	}

	for i := range requestHeaders {
		requestHeaders[i].PreserveRequestValue = !l.SkipAuthStripHeaders
	}

	return requestHeaders
}

func (l *LegacyHeaders) getResponseHeaders() []Header {
	responseHeaders := []Header{}

	if l.SetXAuthRequest {
		responseHeaders = append(responseHeaders, getXAuthRequestHeaders()...)
		if l.PassAccessToken {
			responseHeaders = append(responseHeaders, getXAuthRequestAccessTokenHeader())
		}
	}

	if l.SetBasicAuth {
		responseHeaders = append(responseHeaders, getBasicAuthHeader(l.PreferEmailToUser, l.BasicAuthPassword))
	}

	if l.SetAuthorization {
		responseHeaders = append(responseHeaders, getAuthorizationHeader())
	}

	return responseHeaders
}

func getBasicAuthHeader(preferEmailToUser bool, basicAuthPassword string) Header {
	claim := "user"
	if preferEmailToUser {
		claim = "email"
	}

	return Header{
		Name: "Authorization",
		Values: []HeaderValue{
			{
				ClaimSource: ClaimSource{
					Claim:  claim,
					Prefix: "Basic ",
					BasicAuthPassword: &SecretSource{
						Value: basicAuthPassword,
					},
				},
			},
		},
	}
}

func getPassUserHeaders(preferEmailToUser bool) []Header {
	headers := []Header{
		{
			Name: "X-Forwarded-Groups",
			Values: []HeaderValue{
				{
					ClaimSource: ClaimSource{
						Claim: "groups",
					},
				},
			},
		},
	}

	if preferEmailToUser {
		return append(headers,
			Header{
				Name: "X-Forwarded-User",
				Values: []HeaderValue{
					{
						ClaimSource: ClaimSource{
							Claim: "email",
						},
					},
				},
			},
		)
	}

	return append(headers,
		Header{
			Name: "X-Forwarded-User",
			Values: []HeaderValue{
				{
					ClaimSource: ClaimSource{
						Claim: "user",
					},
				},
			},
		},
		Header{
			Name: "X-Forwarded-Email",
			Values: []HeaderValue{
				{
					ClaimSource: ClaimSource{
						Claim: "email",
					},
				},
			},
		},
	)
}

func getPassAccessTokenHeader() Header {
	return Header{
		Name: "X-Forwarded-Access-Token",
		Values: []HeaderValue{
			{
				ClaimSource: ClaimSource{
					Claim: "access_token",
				},
			},
		},
	}
}

func getAuthorizationHeader() Header {
	return Header{
		Name: "Authorization",
		Values: []HeaderValue{
			{
				ClaimSource: ClaimSource{
					Claim:  "id_token",
					Prefix: "Bearer ",
				},
			},
		},
	}
}

func getPreferredUsernameHeader() Header {
	return Header{
		Name: "X-Forwarded-Preferred-Username",
		Values: []HeaderValue{
			{
				ClaimSource: ClaimSource{
					Claim: "preferred_username",
				},
			},
		},
	}
}

func getXAuthRequestHeaders() []Header {
	headers := []Header{
		{
			Name: "X-Auth-Request-User",
			Values: []HeaderValue{
				{
					ClaimSource: ClaimSource{
						Claim: "user",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Email",
			Values: []HeaderValue{
				{
					ClaimSource: ClaimSource{
						Claim: "email",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Preferred-Username",
			Values: []HeaderValue{
				{
					ClaimSource: ClaimSource{
						Claim: "preferred_username",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Groups",
			Values: []HeaderValue{
				{
					ClaimSource: ClaimSource{
						Claim: "groups",
					},
				},
			},
		},
	}

	return headers
}

func getXAuthRequestAccessTokenHeader() Header {
	return Header{
		Name: "X-Auth-Request-Access-Token",
		Values: []HeaderValue{
			{
				ClaimSource: ClaimSource{
					Claim: "access_token",
				},
			},
		},
	}
}
