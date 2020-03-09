package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

type realClientIPParsder interface {
	GetRealClientIP(http.Header) (net.IP, error)
}

func getRealClientIPParsder(headerKey string) (realClientIPParsder, error) {
	headerKey = http.CanonicalHeaderKey(headerKey)

	if _, ok := xForwardedForCompatableHeaders[headerKey]; ok {
		return &xForwardedForClientIPParser{header: headerKey}, nil
	}

	// TODO: implement the more standardized but more complex `Forwarded` header.
	return nil, fmt.Errorf("The HTTP header key (%s) is either invalid or unsupported", headerKey)
}

var xForwardedForCompatableHeaders = map[string]bool{
	http.CanonicalHeaderKey("X-Forwarded-For"): true,
	http.CanonicalHeaderKey("X-Real-IP"):       true,
	http.CanonicalHeaderKey("X-ProxyUser-IP"):  true,
}

type xForwardedForClientIPParser struct {
	header string
}

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
		return nil, parseFailureError(ipStr, p.header)
	}

	return ip, nil
}

func parseFailureError(ipStr string, h string) error {
	return fmt.Errorf("Unable to parse IP (%s) from %s header", ipStr, http.CanonicalHeaderKey(h))
}
