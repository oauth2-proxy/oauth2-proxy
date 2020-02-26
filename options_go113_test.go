//+build !go1.14

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProxyURLsErrorGo113(t *testing.T) {
	o := testOptions()
	o.Upstreams = append(o.Upstreams, "127.0.0.1:8081")
	err := o.Validate()
	assert.NotEqual(t, nil, err)

	expected := errorMsg([]string{
		"error parsing upstream: parse 127.0.0.1:8081: " +
			"first path segment in URL cannot contain colon"})
	assert.Equal(t, expected, err.Error())
}
