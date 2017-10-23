package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTemplatesCompile(t *testing.T) {
	templates := getTemplates()
	assert.NotEqual(t, templates, nil)
}
