package main

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestSHA(t *testing.T) {
	file := bytes.NewBuffer([]byte("testuser:{SHA}PaVBVZkYqAjCQCu6UBL2xgsnZhw=\n"))
	h, err := NewHtpasswd(file)
	assert.Equal(t, err, nil)

	valid := h.Validate("testuser", "asdf")
	assert.Equal(t, valid, true)
}

func TestBcrypt(t *testing.T) {
	hash1, err := bcrypt.GenerateFromPassword([]byte("password"), 1)
	assert.Equal(t, err, nil)
	hash2, err := bcrypt.GenerateFromPassword([]byte("top-secret"), 2)
	assert.Equal(t, err, nil)

	contents := fmt.Sprintf("testuser1:%s\ntestuser2:%s\n", hash1, hash2)
	file := bytes.NewBuffer([]byte(contents))

	h, err := NewHtpasswd(file)
	assert.Equal(t, err, nil)

	valid := h.Validate("testuser1", "password")
	assert.Equal(t, valid, true)

	valid = h.Validate("testuser2", "top-secret")
	assert.Equal(t, valid, true)
}
