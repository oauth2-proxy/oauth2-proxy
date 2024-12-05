package options

func PicsGetAuthorizationHeader() []Header {
	headers := []Header{
		{
			Name: "Authorization",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim:  "id_token",
						Prefix: "Bearer ",
					},
				},
			},
		},
		{
			Name: "x-auth-request-id-token",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "id_token",
					},
				},
			},
		},
	}
	return headers
}

func PicsGetXAuthIntrospectionValueHeaders() Header {
	return Header{
		Name: "X-Auth-Introspect-Value",
		Values: []HeaderValue{
			{
				ClaimSource: &ClaimSource{
					Claim: "introspect-claims",
				},
			},
		},
	}
}

func PicsGetXAuthInstrospectResponseHeader() Header {
	return Header{
		Name:                 "X-Auth-Introspect-Value",
		PreserveRequestValue: false,
		Values: []HeaderValue{
			{
				ClaimSource: &ClaimSource{
					Claim: "introspect-claims",
				},
			},
		},
	}
}

func PicsGetIdTokenHeader() Header {
	return Header{
		Name:                 "x-auth-request-id-token",
		PreserveRequestValue: false,
		Values: []HeaderValue{
			{
				ClaimSource: &ClaimSource{
					Claim: "id_token",
				},
			},
		},
	}
}
