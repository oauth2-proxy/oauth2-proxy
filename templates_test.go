package main

import (
	"github.com/bmizerany/assert"
	"testing"
)

func TestTemplatesCompile(t *testing.T) {
	templates := getTemplates()
	assert.NotEqual(t, templates, nil)

}
