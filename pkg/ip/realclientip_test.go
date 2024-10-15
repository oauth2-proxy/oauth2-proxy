package ip

import (
	"net"
	"net/http"
	"reflect"
	"testing"

	ipapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/ip"
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
		{"x-envoy-external-address", "", forwardedForType},
		{"cf-connecting-ip", "", forwardedForType},
		{"", "the http header key () is either invalid or unsupported", nil},
		{"Forwarded", "the http header key (Forwarded) is either invalid or unsupported", nil},
		{"2#* @##$$:kd", "the http header key (2#* @##$$:kd) is either invalid or unsupported", nil},
	}

	for _, test := range tests {
		p, err := GetRealClientIPParser(test.header)

		if test.errString == "" {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
			assert.Equal(t, test.errString, err.Error())
		}

		if test.parserType == nil {
			assert.Nil(t, p)
		} else {
			assert.NotNil(t, p)
			assert.Equal(t, test.parserType, reflect.TypeOf(p))
		}

		if xp, ok := p.(*xForwardedForClientIPParser); ok {
			assert.Equal(t, http.CanonicalHeaderKey(test.header), xp.header)
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
		{"nil", "unable to parse ip (nil) from X-Forwarded-For header", nil},
		{"10000.10000.10000.10000", "unable to parse ip (10000.10000.10000.10000) from X-Forwarded-For header", nil},
	}

	for _, test := range tests {
		h := http.Header{}
		h.Add("X-Forwarded-For", test.headerValue)

		ip, err := p.GetRealClientIP(h)

		if test.errString == "" {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
			assert.Equal(t, test.errString, err.Error())
		}

		if test.expectedIP == nil {
			assert.Nil(t, ip)
		} else {
			assert.NotNil(t, ip)
			assert.Equal(t, test.expectedIP, ip)
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

func TestGetRemoteIP(t *testing.T) {
	tests := []struct {
		remoteAddr string
		errString  string
		expectedIP net.IP
	}{
		{"", "unable to get ip and port from http.RemoteAddr ()", nil},
		{"nil", "unable to get ip and port from http.RemoteAddr (nil)", nil},
		{"235.28.129.186", "unable to get ip and port from http.RemoteAddr (235.28.129.186)", nil},
		{"90::45", "unable to get ip and port from http.RemoteAddr (90::45)", nil},
		{"192.168.73.165:14976, 10.4.201.15:18453", "unable to get ip and port from http.RemoteAddr (192.168.73.165:14976, 10.4.201.15:18453)", nil},
		{"10000.10000.10000.10000:8080", "unable to parse ip (10000.10000.10000.10000)", nil},
		{"[::1]:48290", "", net.ParseIP("::1")},
		{"10.254.244.165:62750", "", net.ParseIP("10.254.244.165")},
	}

	for _, test := range tests {
		req := &http.Request{RemoteAddr: test.remoteAddr}

		ip, err := getRemoteIP(req)

		if test.errString == "" {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
			assert.Equal(t, test.errString, err.Error())
		}

		if test.expectedIP == nil {
			assert.Nil(t, ip)
		} else {
			assert.NotNil(t, ip)
			assert.Equal(t, test.expectedIP, ip)
		}
	}
}

func TestGetClientString(t *testing.T) {
	p := &xForwardedForClientIPParser{header: http.CanonicalHeaderKey("X-Forwarded-For")}

	tests := []struct {
		parser             ipapi.RealClientIPParser
		remoteAddr         string
		headerValue        string
		expectedClient     string
		expectedClientFull string
	}{
		// Should fail quietly, only printing warnings to the log
		{nil, "", "", "", ""},
		{p, "127.0.0.1:11950", "", "127.0.0.1", "127.0.0.1"},
		{p, "[::1]:28660", "99.103.56.12", "99.103.56.12", "::1 (99.103.56.12)"},
		{nil, "10.254.244.165:62750", "", "10.254.244.165", "10.254.244.165"},
		// Parser is nil, the contents of X-Forwarded-For should be ignored in all cases.
		{nil, "[2001:470:26:307:a5a1:1177:2ae3:e9c3]:48290", "127.0.0.1", "2001:470:26:307:a5a1:1177:2ae3:e9c3", "2001:470:26:307:a5a1:1177:2ae3:e9c3"},
	}

	for _, test := range tests {
		h := http.Header{}
		h.Add("X-Forwarded-For", test.headerValue)
		req := &http.Request{
			Header:     h,
			RemoteAddr: test.remoteAddr,
		}

		client := GetClientString(test.parser, req, false)
		assert.Equal(t, test.expectedClient, client)

		clientFull := GetClientString(test.parser, req, true)
		assert.Equal(t, test.expectedClientFull, clientFull)
	}
}
