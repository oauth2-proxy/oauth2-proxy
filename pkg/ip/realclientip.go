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
// Returns the `<client>` portion specified in the above document.
// Additionally, is capable of parsing IPs with the port included, for v4 in the format "<ip>:<port>" and for v6 in the
// format "[<ip>]:<port>".  With-port and without-port formats are seamlessly supported concurrently.
func (p xForwardedForClientIPParser) GetRealClientIP(h http.Header) (net.IP, error) {
	var ipStr string
	if realIP := h.Get(p.header); realIP != "" {
		ipStr = realIP
	} else {
		return nil, nil
	}

	// Each successive proxy may append itself, comma separated, to the end of the X-Forwarded-for header.
	// Select only the first IP listed, as it is the client IP recorded by the first proxy.
	if commaIndex := strings.IndexRune(ipStr, ','); commaIndex != -1 {
		ipStr = ipStr[:commaIndex]
	}
	ipStr = strings.TrimSpace(ipStr)

	if ipHost, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = ipHost
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("unable to parse ip (%s) from %s header", ipStr, http.CanonicalHeaderKey(p.header))
	}

	return ip, nil
}

// GetClientIP obtains the perceived end-user IP address from headers if p != nil else from req.RemoteAddr.
func GetClientIP(p ipapi.RealClientIPParser, req *http.Request) (net.IP, error) {
	if p != nil {
		return p.GetRealClientIP(req.Header)
	}
	return getRemoteIP(req)
}

// getRemoteIP obtains the IP of the low-level connected network host
func getRemoteIP(req *http.Request) (net.IP, error) {
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
func GetClientString(p ipapi.RealClientIPParser, req *http.Request, full bool) (s string) {
	var realClientIPStr string
	if p != nil {
		if realClientIP, err := p.GetRealClientIP(req.Header); err == nil && realClientIP != nil {
			realClientIPStr = realClientIP.String()
		}
	}

	var remoteIPStr string
	if remoteIP, err := getRemoteIP(req); err == nil {
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
