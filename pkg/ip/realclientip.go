package ip

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	ipapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/ip"
)

func GetRealClientIPParser(headerKey string) (ipapi.RealClientIPParser, error) {
	headerKey = http.CanonicalHeaderKey(headerKey)

	switch headerKey {
	case http.CanonicalHeaderKey("X-Forwarded-For"),
		http.CanonicalHeaderKey("X-Real-IP"),
		http.CanonicalHeaderKey("X-ProxyUser-IP"),
		http.CanonicalHeaderKey("X-Envoy-External-Address"),
		// Cloudflare specific Real-IP header
		http.CanonicalHeaderKey("CF-Connecting-IP"):
		return &xForwardedForClientIPParser{header: headerKey}, nil
	}

	// TODO: implement the more standardized but more complex `Forwarded` header.
	return nil, fmt.Errorf("the http header key (%s) is either invalid or unsupported", headerKey)
}

type xForwardedForClientIPParser struct {
	header string
}

// GetRealClientIP obtain the IP address of the end-user (not proxy).
// Parses headers sharing the format as specified by:
// * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For.
// Additionally, is capable of parsing IPs with the port included, for v4 in the format "<ip>:<port>" and for v6 in the
// format "[<ip>]:<port>".  With-port and without-port formats are seamlessly supported concurrently.
//
// Each successive proxy may append itself, comma separated, to the end of the header. Blindly trusting the leftmost
// (client-supplied) entry lets an untrusted client spoof it, so instead this walks the chain from the right (the
// most recently appended hop) and skips over entries that are themselves trusted proxies, returning the first entry
// that isn't -- that's the address a trusted proxy is vouching for, which the originating client cannot forge. If
// the direct connecting peer (remoteAddr) is not itself a trusted proxy, the header is ignored entirely and
// remoteAddr is returned, since nothing in a client-controlled header can be believed in that case.
func (p xForwardedForClientIPParser) GetRealClientIP(h http.Header, remoteAddr net.IP, trusted ipapi.TrustedProxies) (net.IP, error) {
	raw := h.Get(p.header)
	if raw == "" {
		return nil, nil
	}

	isTrusted := func(candidate net.IP) bool {
		return trusted == nil || candidate == nil || trusted.Has(candidate)
	}

	if !isTrusted(remoteAddr) {
		return remoteAddr, nil
	}

	hops := strings.Split(raw, ",")

	var lastParsed net.IP
	for i := len(hops) - 1; i >= 0; i-- {
		hopIP, err := parseHopIP(hops[i], p.header)
		if err != nil {
			return nil, err
		}
		if !isTrusted(hopIP) {
			return hopIP, nil
		}
		lastParsed = hopIP
	}

	// Every hop was itself a trusted proxy; fall back to the leftmost (oldest) entry, matching the historical
	// behavior for when trusted proxies aren't restricted (trust-all default).
	return lastParsed, nil
}

// parseHopIP parses a single comma-separated entry of a forwarded header into an IP,
// stripping surrounding whitespace and an optional port.
func parseHopIP(hop string, header string) (net.IP, error) {
	ipStr := strings.TrimSpace(hop)

	if ipHost, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = ipHost
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("unable to parse ip (%s) from %s header", ipStr, http.CanonicalHeaderKey(header))
	}

	return ip, nil
}

// GetClientIP obtains the perceived end-user IP address from headers if p != nil else from req.RemoteAddr.
func GetClientIP(p ipapi.RealClientIPParser, req *http.Request, trusted ipapi.TrustedProxies) (net.IP, error) {
	if p != nil {
		// Best-effort: an unparseable RemoteAddr becomes nil, which GetRealClientIP treats as trusted
		// (e.g. unix sockets, or tests that don't set RemoteAddr), so this never blocks the header path.
		remoteAddr, _ := getRemoteIP(req)
		return p.GetRealClientIP(req.Header, remoteAddr, trusted)
	}
	return getRemoteIP(req)
}

// getRemoteIP obtains the IP of the low-level connected network host
func getRemoteIP(req *http.Request) (net.IP, error) {
	// Unix domain sockets set RemoteAddr to "@" which has no meaningful IP.
	// https://github.com/golang/go/blob/0fa53e41f122b1661d0678a6d36d71b7b5ad031d/src/syscall/syscall_linux.go#L506-L511
	if req.RemoteAddr == "@" {
		return nil, nil
	}

	//revive:disable:indent-error-flow
	if ipStr, _, err := net.SplitHostPort(req.RemoteAddr); err != nil {
		return nil, fmt.Errorf("unable to get ip and port from http.RemoteAddr (%s)", req.RemoteAddr)
	} else if ip := net.ParseIP(ipStr); ip != nil {
		return ip, nil
	} else {
		return nil, fmt.Errorf("unable to parse ip (%s)", ipStr)
	}
	//revive:enable:indent-error-flow
}

// GetClientString obtains the human readable string of the remote IP and optionally the real client IP if available
func GetClientString(p ipapi.RealClientIPParser, req *http.Request, full bool, trusted ipapi.TrustedProxies) (s string) {
	remoteIP, remoteErr := getRemoteIP(req)

	var realClientIPStr string
	if p != nil {
		if realClientIP, err := p.GetRealClientIP(req.Header, remoteIP, trusted); err == nil && realClientIP != nil {
			realClientIPStr = realClientIP.String()
		}
	}

	var remoteIPStr string
	if remoteErr == nil && remoteIP != nil {
		remoteIPStr = remoteIP.String()
	}

	if !full && realClientIPStr != "" {
		return realClientIPStr
	}
	if full && realClientIPStr != "" {
		return fmt.Sprintf("%s (%s)", remoteIPStr, realClientIPStr)
	}
	return remoteIPStr
}
