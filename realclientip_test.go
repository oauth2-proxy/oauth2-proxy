package main

import (
	"net"
	"net/http"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetRealClientIPParser(t *testing.T) {
	forwardedForType := reflect.TypeOf((*xForwardedForClientIPParser)(nil))

	tests := []struct {
		header     string
		errString  string
		parserType reflect.Type
	}{
		{"X-Forwarded-For", "", forwardedForType},
		{"X-REAL-IP", "", forwardedForType},
		{"x-proxyuser-ip", "", forwardedForType},
		{"", "The HTTP header key () is either invalid or unsupported", nil},
		{"Forwarded", "The HTTP header key (Forwarded) is either invalid or unsupported", nil},
		{"2#* @##$$:kd", "The HTTP header key (2#* @##$$:kd) is either invalid or unsupported", nil},
	}

	for _, test := range tests {
		p, err := getRealClientIPParser(test.header)

		if test.errString == "" {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
			assert.Equal(t, err.Error(), test.errString)
		}

		if test.parserType == nil {
			assert.Nil(t, p)
		} else {
			assert.NotNil(t, p)
			assert.Equal(t, reflect.TypeOf(p), test.parserType)
		}

		if xp, ok := p.(*xForwardedForClientIPParser); ok {
			assert.Equal(t, xp.header, http.CanonicalHeaderKey(test.header))
		}
	}
}

func TestXForwardedForClientIPParser(t *testing.T) {
	p := &xForwardedForClientIPParser{header: http.CanonicalHeaderKey("X-Forwarded-For")}

	tests := []struct {
		headerValue string
		errString   string
		expectedIP  net.IP
	}{
		{"", "", nil},
		{"1.2.3.4", "", net.ParseIP("1.2.3.4")},
		{"10::23", "", net.ParseIP("10::23")},
		{"::1", "", net.ParseIP("::1")},
		{"[::1]:1234", "", net.ParseIP("::1")},
		{"10.0.10.11:1234", "", net.ParseIP("10.0.10.11")},
		{"192.168.10.50, 10.0.0.1, 1.2.3.4", "", net.ParseIP("192.168.10.50")},
		{"nil", "Unable to parse IP (nil) from X-Forwarded-For header", nil},
		{"10000.10000.10000.10000", "Unable to parse IP (10000.10000.10000.10000) from X-Forwarded-For header", nil},
	}

	for _, test := range tests {
		h := http.Header{}
		h.Add("X-Forwarded-For", test.headerValue)

		ip, err := p.GetRealClientIP(h)

		if test.errString == "" {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
			assert.Equal(t, err.Error(), test.errString)
		}

		if test.expectedIP == nil {
			assert.Nil(t, ip)
		} else {
			assert.NotNil(t, ip)
			assert.Equal(t, ip, test.expectedIP)
		}
	}
}

func TestXForwardedForClientIPParserIgnoresOthers(t *testing.T) {
	p := &xForwardedForClientIPParser{header: http.CanonicalHeaderKey("X-Forwarded-For")}

	h := http.Header{}
	expectedIPString := "192.168.10.50"
	h.Add("X-Real-IP", "10.0.0.1")
	h.Add("X-ProxyUser-IP", "10.0.0.1")
	h.Add("X-Forwarded-For", expectedIPString)
	ip, err := p.GetRealClientIP(h)
	assert.Nil(t, err)
	assert.NotNil(t, ip)
	assert.Equal(t, ip, net.ParseIP(expectedIPString))
}
