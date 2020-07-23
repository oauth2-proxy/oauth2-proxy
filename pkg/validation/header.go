package validation

import (
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

func validateHeaders(headers []options.Header) []string {
	msgs := []string{}
	names := make(map[string]struct{})

	for _, header := range headers {
		msgs = append(msgs, validateHeader(header, names)...)
	}
	return msgs
}

func validateHeader(header options.Header, names map[string]struct{}) []string {
	msgs := []string{}

	if header.Name == "" {
		msgs = append(msgs, "header has empty name: names are required for all headers")
	}

	if _, ok := names[header.Name]; ok {
		msgs = append(msgs, fmt.Sprintf("multiple headers found with name %q: header names must be unique", header.Name))
	}

	for _, value := range header.Values {
		msgs = append(msgs, validateHeaderValue(header.Name, value)...)
	}
	return msgs
}

func validateHeaderValue(name string, value options.HeaderValue) []string {
	switch {
	case value.SecretSource != nil && value.ClaimSource == nil:
		return prefixValues("invalid header value: ", validateSecretSource(*value.SecretSource))
	case value.SecretSource == nil && value.ClaimSource != nil:
		return validateHeaderValueClaimSource(*value.ClaimSource)
	default:
		return []string{fmt.Sprintf("header %q value has multiple entries: only one entry per value is allowed", name)}
	}
}

func validateHeaderValueClaimSource(claim options.ClaimSource) []string {
	if claim.BasicAuthPassword != nil {
		return prefixValues("invalid basicAuthPassword: ", validateSecretSource(*claim.BasicAuthPassword))
	}
	return []string{}
}
