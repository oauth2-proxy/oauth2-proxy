package main

import (
	"fmt"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetRealClientIPParser(t *testing.T) {
	var p RealClientIPParser
	var err error

	p, err = GetRealClientIPParser("X-Forwarded-For")
	assert.Nil(t, err)
	assert.Equal(t, reflect.TypeOf(p), reflect.TypeOf((*xForwardedForClientIPParser)(nil)))

	p, err = GetRealClientIPParser("X-REAL-IP")
	assert.Nil(t, err)
	assert.Equal(t, reflect.TypeOf(p), reflect.TypeOf((*xForwardedForClientIPParser)(nil)))
	if xp, ok := p.(*xForwardedForClientIPParser); ok {
		assert.Equal(t, xp.header, http.CanonicalHeaderKey("X-Real-Ip"))
	} else {
		panic("Type of local variable p changed without assignment?")
	}

	p, err = GetRealClientIPParser("x-proxyuser-ip")
	assert.Nil(t, err)
	assert.Equal(t, reflect.TypeOf(p), reflect.TypeOf((*xForwardedForClientIPParser)(nil)))

	p, err = GetRealClientIPParser("")
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "The HTTP header key () is either invalid or unsupported")
	assert.Nil(t, p)

	p, err = GetRealClientIPParser("Forwarded")
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "The HTTP header key (Forwarded) is either invalid or unsupported")
	assert.Nil(t, p)

	p, err = GetRealClientIPParser("2#* @##$$:kd")
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "The HTTP header key (2#* @##$$:kd) is either invalid or unsupported")
	assert.Nil(t, p)
}

func TestXForwardedForClientIPParser(t *testing.T) {
	var p *xForwardedForClientIPParser
	var ip net.IP
	var expectedIPString string
	var err error
	var h http.Header

	p = &xForwardedForClientIPParser{header: http.CanonicalHeaderKey("X-Forwarded-For")}

	h = http.Header{}
	ip, err = p.GetRealClientIP(h)
	assert.Nil(t, err)
	assert.Nil(t, ip)

	h = http.Header{}
	h.Add("X-Forwarded-For", "")
	ip, err = p.GetRealClientIP(h)
	assert.Nil(t, err)
	assert.Nil(t, ip)

	h = http.Header{}
	expectedIPString = "1.2.3.4"
	h.Add("X-Forwarded-For", expectedIPString)
	ip, err = p.GetRealClientIP(h)
	assert.Nil(t, err)
	assert.NotNil(t, ip)
	assert.Equal(t, ip, net.ParseIP(expectedIPString))

	h = http.Header{}
	expectedIPString = "10::23"
	h.Add("X-Forwarded-For", expectedIPString)
	ip, err = p.GetRealClientIP(h)
	assert.Nil(t, err)
	assert.NotNil(t, ip)
	assert.Equal(t, ip, net.ParseIP(expectedIPString))

	h = http.Header{}
	expectedIPString = "::1"
	h.Add("X-Forwarded-For", fmt.Sprintf("[%s]:1234", expectedIPString))
	ip, err = p.GetRealClientIP(h)
	assert.Nil(t, err)
	assert.NotNil(t, ip)
	assert.Equal(t, ip, net.ParseIP(expectedIPString))

	h = http.Header{}
	expectedIPString = "10.0.10.11"
	h.Add("X-Forwarded-For", fmt.Sprintf("%s:1234", expectedIPString))
	ip, err = p.GetRealClientIP(h)
	assert.Nil(t, err)
	assert.NotNil(t, ip)
	assert.Equal(t, ip, net.ParseIP(expectedIPString))

	h = http.Header{}
	expectedIPString = "192.168.10.50"
	h.Add("X-Real-IP", "10.0.0.1")
	h.Add("X-ProxyUser-IP", "10.0.0.1")
	h.Add("X-Forwarded-For", expectedIPString)
	ip, err = p.GetRealClientIP(h)
	assert.Nil(t, err)
	assert.NotNil(t, ip)
	assert.Equal(t, ip, net.ParseIP(expectedIPString))

	h = http.Header{}
	expectedIPString = "192.168.10.50"
	h.Add("X-Forwarded-For", strings.Join([]string{expectedIPString, "10.0.0.1", "1.2.3.4"}, ", "))
	ip, err = p.GetRealClientIP(h)
	assert.Nil(t, err)
	assert.NotNil(t, ip)
	assert.Equal(t, ip, net.ParseIP(expectedIPString))

	h = http.Header{}
	h.Add("X-Forwarded-For", "nil")
	ip, err = p.GetRealClientIP(h)
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "Unable to parse IP (nil) from X-Forwarded-For header")
	assert.Nil(t, ip)

	h = http.Header{}
	h.Add("X-Forwarded-For", "10000.10000.10000.10000")
	ip, err = p.GetRealClientIP(h)
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "Unable to parse IP (10000.10000.10000.10000) from X-Forwarded-For header")
	assert.Nil(t, ip)
}
