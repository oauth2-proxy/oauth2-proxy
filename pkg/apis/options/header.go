package options

import "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"

// Header represents an individual header that will be added to a request or
// response header.
type Header struct {
	// Name is the header name to be used for this set of values.
	// Names should be unique within a list of Headers.
	Name string `yaml:"name,omitempty"`

	// PreserveRequestValue determines whether any values for this header
	// should be preserved for the request to the upstream server.
	// This option only applies to injected request headers.
	// Defaults to false (headers that match this header will be stripped).
	PreserveRequestValue *bool `yaml:"preserveRequestValue,omitempty"`

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
	Values []HeaderValue `yaml:"values,omitempty"`
}

// HeaderValue represents a single header value and the sources that can
// make up the header value
type HeaderValue struct {
	// Allow users to load the value from a secret source
	*SecretSource `yaml:"secretSource,omitempty"`

	// Allow users to load the value from a session claim
	*ClaimSource `yaml:"claimSource,omitempty"`
}

// ClaimSource allows loading a header value from a claim within the session
type ClaimSource struct {
	// Claim is the name of the claim in the session that the value should be
	// loaded from. Available claims: `access_token` `id_token` `created_at`
	// `expires_on` `refresh_token` `email` `user` `groups` `preferred_username`.
	Claim string `yaml:"claim,omitempty"`

	// Prefix is an optional prefix that will be prepended to the value of the
	// claim if it is non-empty.
	Prefix string `yaml:"prefix,omitempty"`

	// BasicAuthPassword converts this claim into a basic auth header.
	// Note the value of claim will become the basic auth username and the
	// basicAuthPassword will be used as the password value.
	BasicAuthPassword *SecretSource `yaml:"basicAuthPassword,omitempty"`
}

// EnsureDefaults sets any default values for Header fields.
func (h *Header) EnsureDefaults() {
	if h.PreserveRequestValue == nil {
		h.PreserveRequestValue = ptr.Ptr(false)
	}
	for i := range h.Values {
		h.Values[i].EnsureDefaults()
	}
}

// EnsureDefaults sets any default values for HeaderValue fields.
func (hv *HeaderValue) EnsureDefaults() {
	if hv.ClaimSource != nil {
		hv.ClaimSource.EnsureDefaults()
	}
	if hv.SecretSource != nil {
		hv.SecretSource.EnsureDefaults()
	}
}

// EnsureDefaults sets any default values for ClaimSource fields.
func (hc *ClaimSource) EnsureDefaults() {
	// No defaults to set currently
}
