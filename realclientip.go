package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

type realClientIPParser interface {
	GetRealClientIP(http.Header) (net.IP, error)
}

func getRealClientIPParser(headerKey string) (realClientIPParser, error) {
	headerKey = http.CanonicalHeaderKey(headerKey)

	switch headerKey {
	case http.CanonicalHeaderKey("X-Forwarded-For"), http.CanonicalHeaderKey("X-Real-IP"), http.CanonicalHeaderKey("X-ProxyUser-IP"):
		return &xForwardedForClientIPParser{header: headerKey}, nil
	}

	// TODO: implement the more standardized but more complex `Forwarded` header.
	return nil, fmt.Errorf("The HTTP header key (%s) is either invalid or unsupported", headerKey)
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

	if commaIndex := strings.IndexRune(ipStr, ','); commaIndex != -1 {
		ipStr = ipStr[:commaIndex]
	}
	ipStr = strings.TrimSpace(ipStr)

	if ipHost, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = ipHost
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("Unable to parse IP (%s) from %s header", ipStr, http.CanonicalHeaderKey(p.header))
	}

	return ip, nil
}
