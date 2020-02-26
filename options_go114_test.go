//+build !go1.13 go1.14

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProxyURLsErrorGo114(t *testing.T) {
	o := testOptions()
	o.Upstreams = append(o.Upstreams, "127.0.0.1:8081")
	err := o.Validate()
	assert.NotEqual(t, nil, err)

	// The error message for net/url url.Parse has changed slightly since go1.14.
	// https: //github.com/golang/go/commit/64cfe9fe22113cd6bc05a2c5d0cbe872b1b57860
	expected := errorMsg([]string{
		"error parsing upstream: parse \"127.0.0.1:8081\": " +
			"first path segment in URL cannot contain colon"})
	assert.Equal(t, expected, err.Error())
}
