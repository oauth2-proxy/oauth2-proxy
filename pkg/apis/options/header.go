package options

// Header represents an individual header that will be added to a request or
// response header.
type Header struct {
	// Name is the header name to be used for this set of values.
	// Names should be unique within a list of Headers.
	Name string `json:"name,omitempty"`

	// PreserveRequestValue determines whether any values for this header
	// should be preserved for the request to the upstream server.
	// This option only applies to injected request headers.
	// Defaults to false (headers that match this header will be stripped).
	PreserveRequestValue bool `json:"preserveRequestValue,omitempty"`

	// Values contains the desired values for this header
	Values []HeaderValue `json:"values,omitempty"`
}

// HeaderValue represents a single header value and the sources that can
// make up the header value
type HeaderValue struct {
	// Allow users to load the value from a secret source
	*SecretSource `json:",omitempty"`

	// Allow users to load the value from a session claim
	*ClaimSource `json:",omitempty"`
}

// ClaimSource allows loading a header value from a claim within the session
type ClaimSource struct {
	// Claim is the name of the claim in the session that the value should be
	// loaded from.
	Claim string `json:"claim,omitempty"`

	// Prefix is an optional prefix that will be prepended to the value of the
	// claim if it is non-empty.
	Prefix string `json:"prefix,omitempty"`

	// BasicAuthPassword converts this claim into a basic auth header.
	// Note the value of claim will become the basic auth username and the
	// basicAuthPassword will be used as the password value.
	BasicAuthPassword *SecretSource `json:"basicAuthPassword,omitempty"`
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
				ClaimSource: &ClaimSource{
					Claim:  claim,
					Prefix: "Basic ",
					BasicAuthPassword: &SecretSource{
						Value: []byte(basicAuthPassword),
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
					ClaimSource: &ClaimSource{
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
						ClaimSource: &ClaimSource{
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
					ClaimSource: &ClaimSource{
						Claim: "user",
					},
				},
			},
		},
		Header{
			Name: "X-Forwarded-Email",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
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
				ClaimSource: &ClaimSource{
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
				ClaimSource: &ClaimSource{
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
				ClaimSource: &ClaimSource{
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
					ClaimSource: &ClaimSource{
						Claim: "user",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Email",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "email",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Preferred-Username",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "preferred_username",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Groups",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
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
				ClaimSource: &ClaimSource{
					Claim: "access_token",
				},
			},
		},
	}
}
