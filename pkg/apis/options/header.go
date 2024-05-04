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

	// InsecureSkipHeaderNormalization disables normalizing the header name
	// According to RFC 7230 Section 3.2 there aren't any rules about
	// capitalization of header names, but the standard practice is to use
	// Title-Case (e.g. X-Forwarded-For). By default, header names will be
	// normalized to Title-Case and any incoming headers that match will be
	// treated as the same header. Additionally underscores (_) in header names
	// will be converted to dashes (-) when normalizing.
	// Defaults to false (header names will be normalized).
	InsecureSkipHeaderNormalization bool `json:"InsecureSkipHeaderNormalization,omitempty"`

	// Values contains the desired values for this header
	Values []HeaderValue `json:"values,omitempty"`
}

// HeaderValue represents a single header value and the sources that can
// make up the header value
type HeaderValue struct {
	// Allow users to load the value from a secret source
	*SecretSource `json:"secretSource,omitempty"`

	// Allow users to load the value from a session claim
	*ClaimSource `json:"claimSource,omitempty"`
}

// ClaimSource allows loading a header value from a claim within the session
type ClaimSource struct {
	// Claim is the name of the claim in the session that the value should be
	// loaded from. Available claims: `access_token` `id_token` `created_at`
	// `expires_on` `refresh_token` `email` `user` `groups` `preferred_username`.
	Claim string `json:"claim,omitempty"`

	// Prefix is an optional prefix that will be prepended to the value of the
	// claim if it is non-empty.
	Prefix string `json:"prefix,omitempty"`

	// BasicAuthPassword converts this claim into a basic auth header.
	// Note the value of claim will become the basic auth username and the
	// basicAuthPassword will be used as the password value.
	BasicAuthPassword *SecretSource `json:"basicAuthPassword,omitempty"`
}
