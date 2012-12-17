package main

import (
	"bytes"
	"github.com/bmizerany/assert"
	"testing"
)

func TestHtpasswd(t *testing.T) {
	file := bytes.NewBuffer([]byte("testuser:{SHA}PaVBVZkYqAjCQCu6UBL2xgsnZhw=\n"))
	h, err := NewHtpasswd(file)
	assert.Equal(t, err, nil)

	valid := h.Validate("testuser", "asdf")
	assert.Equal(t, valid, true)
}
