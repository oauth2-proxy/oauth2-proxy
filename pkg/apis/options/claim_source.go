package options

import "fmt"

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

// MarshalYAML implements the yaml.Marshaler interface for ClaimSource.
// This is only necessary for the conversion workflow from toml to yaml
func (c *ClaimSource) MarshalYAML() (interface{}, error) {
	if c == nil {
		return nil, nil
	}

	mapped := make(map[string]interface{})
	if c.Claim != "" {
		mapped["claim"] = c.Claim
	}
	if c.Prefix != "" {
		mapped["prefix"] = c.Prefix
	}
	if c.BasicAuthPassword != nil {
		basicAuthPasswordYAML, err := c.BasicAuthPassword.MarshalYAML()
		if err != nil {
			return nil, fmt.Errorf("error marshaling basicAuthPassword for ClaimSource: %w", err)
		}
		mapped["basicAuthPassword"] = basicAuthPasswordYAML
	}

	return mapped, nil
}
