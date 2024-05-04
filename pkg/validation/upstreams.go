package validation

import (
	"fmt"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

func validateUpstreams(upstreams options.UpstreamConfig) []string {
	msgs := []string{}
	ids := make(map[string]struct{})
	paths := make(map[string]struct{})

	for _, upstream := range upstreams.Upstreams {
		msgs = append(msgs, validateUpstream(upstream, ids, paths)...)
	}

	return msgs
}

// validateUpstream validates that the upstream has valid options and that
// the ids and paths are unique across all options
func validateUpstream(upstream options.Upstream, ids, paths map[string]struct{}) []string {
	msgs := []string{}

	if upstream.ID == "" {
		msgs = append(msgs, "upstream has empty id: ids are required for all upstreams")
	}
	if upstream.Path == "" {
		msgs = append(msgs, fmt.Sprintf("upstream %q has empty path: paths are required for all upstreams", upstream.ID))
	}

	// Ensure upstream IDs are unique
	if _, ok := ids[upstream.ID]; ok {
		msgs = append(msgs, fmt.Sprintf("multiple upstreams found with id %q: upstream ids must be unique", upstream.ID))
	}
	ids[upstream.ID] = struct{}{}

	// Ensure upstream Paths are unique
	if _, ok := paths[upstream.Path]; ok {
		msgs = append(msgs, fmt.Sprintf("multiple upstreams found with path %q: upstream paths must be unique", upstream.Path))
	}
	paths[upstream.Path] = struct{}{}

	msgs = append(msgs, validateUpstreamURI(upstream)...)
	msgs = append(msgs, validateStaticUpstream(upstream)...)
	return msgs
}

// validateStaticUpstream checks that the StaticCode is only set when Static
// is set, and that any options that do not make sense for a static upstream
// are not set.
func validateStaticUpstream(upstream options.Upstream) []string {
	msgs := []string{}

	if !upstream.Static && upstream.StaticCode != nil {
		msgs = append(msgs, fmt.Sprintf("upstream %q has staticCode (%d), but is not a static upstream, set 'static' for a static response", upstream.ID, *upstream.StaticCode))
	}

	// Checks after this only make sense when the upstream is static
	if !upstream.Static {
		return msgs
	}

	if upstream.URI != "" {
		msgs = append(msgs, fmt.Sprintf("upstream %q has uri, but is a static upstream, this will have no effect.", upstream.ID))
	}
	if upstream.InsecureSkipTLSVerify {
		msgs = append(msgs, fmt.Sprintf("upstream %q has insecureSkipTLSVerify, but is a static upstream, this will have no effect.", upstream.ID))
	}
	if upstream.FlushInterval != nil && *upstream.FlushInterval != options.DefaultUpstreamFlushInterval {
		msgs = append(msgs, fmt.Sprintf("upstream %q has flushInterval, but is a static upstream, this will have no effect.", upstream.ID))
	}
	if upstream.PassHostHeader != nil {
		msgs = append(msgs, fmt.Sprintf("upstream %q has passHostHeader, but is a static upstream, this will have no effect.", upstream.ID))
	}
	if upstream.ProxyWebSockets != nil {
		msgs = append(msgs, fmt.Sprintf("upstream %q has proxyWebSockets, but is a static upstream, this will have no effect.", upstream.ID))
	}

	return msgs
}

func validateUpstreamURI(upstream options.Upstream) []string {
	msgs := []string{}

	if !upstream.Static && upstream.URI == "" {
		msgs = append(msgs, fmt.Sprintf("upstream %q has empty uri: uris are required for all non-static upstreams", upstream.ID))
		return msgs
	}

	// Checks after this only make sense the upstream is not static
	if upstream.Static {
		return msgs
	}

	u, err := url.Parse(upstream.URI)
	if err != nil {
		msgs = append(msgs, fmt.Sprintf("upstream %q has invalid uri: %v", upstream.ID, err))
		return msgs
	}

	switch u.Scheme {
	case "http", "https", "file", "unix":
		// Valid, do nothing
	default:
		msgs = append(msgs, fmt.Sprintf("upstream %q has invalid scheme: %q", upstream.ID, u.Scheme))
	}

	return msgs
}
