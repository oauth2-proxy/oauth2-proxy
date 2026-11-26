package ip

import (
	"net"
	"net/http"
	"reflect"
	"testing"

	ipapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/ip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestGetClientIPFromTrustedProxy(t *testing.T) {
	parser, err := GetRealClientIPParser("X-Forwarded-For")
	require.NoError(t, err)
	trustedProxies, err := ParseNetSet([]string{"192.0.2.0/24", "2001:db8:1::/48"})
	require.NoError(t, err)

	tests := []struct {
		name         string
		headerValues []string
		expectedIP   string
		errString    string
	}{
		{"Ignores spoofed leftmost entry", []string{"10.0.0.5, 198.51.100.23"}, "198.51.100.23", ""},
		{"Walks past trusted intermediate proxies", []string{"198.51.100.23, 192.0.2.20, 192.0.2.21"}, "198.51.100.23", ""},
		{"Uses leftmost entry when entire chain is trusted", []string{"192.0.2.30, 192.0.2.20"}, "192.0.2.30", ""},
		{"Repeated fields preserve chain order", []string{"10.0.0.5", "198.51.100.23, 192.0.2.20", "192.0.2.21"}, "198.51.100.23", ""},
		{"Whitespace and IPv4 port", []string{" 198.51.100.23:1234 ,\t192.0.2.20:443 "}, "198.51.100.23", ""},
		{"IPv6 client and proxies", []string{"2001:db8:2::23, 2001:db8:1::20"}, "2001:db8:2::23", ""},
		{"IPv6 port and mixed chain", []string{" [2001:db8:2::23]:1234 , [2001:db8:1::20]:443, 192.0.2.20"}, "2001:db8:2::23", ""},
		{"Stops at first untrusted hop", []string{"10.0.0.5, 198.51.100.22, 198.51.100.23, 192.0.2.20"}, "198.51.100.23", ""},
		{"Ignores malformed entry beyond boundary", []string{"invalid, 198.51.100.23, 192.0.2.20"}, "198.51.100.23", ""},
		{"Missing header", nil, "", ""},
		{"Empty header", []string{""}, "", ""},
		{"Whitespace only", []string{" \t"}, "", "unable to parse ip () from X-Forwarded-For header"},
		{"Malformed rightmost hop", []string{"10.0.0.5, invalid"}, "", "unable to parse ip (invalid) from X-Forwarded-For header"},
		{"Malformed relevant intermediate hop", []string{"10.0.0.5, invalid, 192.0.2.20"}, "", "unable to parse ip (invalid) from X-Forwarded-For header"},
		{"Malformed leftmost in otherwise trusted chain", []string{"invalid, 192.0.2.20"}, "", "unable to parse ip (invalid) from X-Forwarded-For header"},
		{"Empty intermediate hop", []string{"10.0.0.5,,192.0.2.20"}, "", "unable to parse ip () from X-Forwarded-For header"},
		{"Empty last field", []string{"10.0.0.5", ""}, "", "unable to parse ip () from X-Forwarded-For header"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := &http.Request{Header: http.Header{}}
			for _, value := range test.headerValues {
				req.Header.Add("X-Forwarded-For", value)
			}

			clientIP, err := GetClientIPFromTrustedProxy(parser, req, trustedProxies)
			if test.errString != "" {
				assert.EqualError(t, err, test.errString)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, net.ParseIP(test.expectedIP), clientIP)
		})
	}
}

func TestGetClientIPFromTrustedProxyConfiguration(t *testing.T) {
	xff, err := GetRealClientIPParser("X-Forwarded-For")
	require.NoError(t, err)
	realIP, err := GetRealClientIPParser("X-Real-IP")
	require.NoError(t, err)
	trustAll, err := ParseNetSet([]string{"0.0.0.0/0", "::/0"})
	require.NoError(t, err)

	tests := []struct {
		name           string
		parser         ipapi.RealClientIPParser
		trustedProxies *NetSet
		expectedIP     string
		errString      string
	}{
		{"Nil parser", nil, trustAll, "", "real client IP parser is required"},
		{"Nil trusted proxies", xff, nil, "", "trusted proxy list is required to parse X-Forwarded-For"},
		{"Empty trusted proxies", xff, NewNetSet(), "2001:db8::23", ""},
		{"Trust all retains leftmost compatibility", xff, trustAll, "10.0.0.5", ""},
		{"Single value header", realIP, trustAll, "198.51.100.23", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := &http.Request{Header: http.Header{
				"X-Forwarded-For": {"10.0.0.5, 2001:db8::23"},
				"X-Real-Ip":       {"198.51.100.23"},
			}}
			clientIP, err := GetClientIPFromTrustedProxy(test.parser, req, test.trustedProxies)
			if test.errString != "" {
				assert.EqualError(t, err, test.errString)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, net.ParseIP(test.expectedIP), clientIP)
		})
	}
}

func TestGetRemoteIP(t *testing.T) {
	tests := []struct {
		remoteAddr string
		errString  string
		expectedIP net.IP
	}{
		// Unix domain sockets set RemoteAddr to "@"
		{"@", "", nil},
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
	trustedProxies, err := ParseNetSet([]string{"192.0.2.0/24", "2001:db8:1::/48"})
	require.NoError(t, err)

	tests := []struct {
		parser             ipapi.RealClientIPParser
		remoteAddr         string
		headerValue        string
		expectedClient     string
		expectedClientFull string
	}{
		// Preserve transport-only output when no client address is available.
		{nil, "", "", "", ""},
		// Unix domain socket — no IP available
		{nil, "@", "", "", ""},
		{p, "127.0.0.1:11950", "", "127.0.0.1", "127.0.0.1"},
		{p, "[::1]:28660", "99.103.56.12", "99.103.56.12", "::1 (99.103.56.12)"},
		{nil, "10.254.244.165:62750", "", "10.254.244.165", "10.254.244.165"},
		// Parser is nil, the contents of X-Forwarded-For should be ignored in all cases.
		{nil, "[2001:470:26:307:a5a1:1177:2ae3:e9c3]:48290", "127.0.0.1", "2001:470:26:307:a5a1:1177:2ae3:e9c3", "2001:470:26:307:a5a1:1177:2ae3:e9c3"},
		{p, "192.0.2.10:443", "10.0.0.5, 198.51.100.23, 192.0.2.20", "198.51.100.23", "192.0.2.10 (198.51.100.23)"},
		{p, "[2001:db8:1::10]:443", "[2001:db8:2::23]:1234, 2001:db8:1::20", "2001:db8:2::23", "2001:db8:1::10 (2001:db8:2::23)"},
		{p, "192.0.2.10:443", "10.0.0.5, invalid, 192.0.2.20", "192.0.2.10", "192.0.2.10"},
		{p, "192.0.2.10:443", "invalid, 198.51.100.23", "198.51.100.23", "192.0.2.10 (198.51.100.23)"},
		{p, "192.0.2.10:443", "192.0.2.30, 192.0.2.20", "192.0.2.30", "192.0.2.10 (192.0.2.30)"},
		{p, "@", "198.51.100.23, 192.0.2.20", "198.51.100.23", " (198.51.100.23)"},
		{p, "@", "invalid", "", ""},
	}

	for _, test := range tests {
		h := http.Header{}
		h.Add("X-Forwarded-For", test.headerValue)
		req := &http.Request{
			Header:     h,
			RemoteAddr: test.remoteAddr,
		}

		client := GetClientString(test.parser, req, trustedProxies, false)
		assert.Equal(t, test.expectedClient, client)

		clientFull := GetClientString(test.parser, req, trustedProxies, true)
		assert.Equal(t, test.expectedClientFull, clientFull)
	}
}
