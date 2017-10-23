package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type envTest struct {
	testField string `cfg:"target_field" env:"TEST_ENV_FIELD"`
}

func TestLoadEnvForStruct(t *testing.T) {

	cfg := make(EnvOptions)
	cfg.LoadEnvForStruct(&envTest{})

	_, ok := cfg["target_field"]
	assert.Equal(t, ok, false)

	os.Setenv("TEST_ENV_FIELD", "1234abcd")
	cfg.LoadEnvForStruct(&envTest{})
	v := cfg["target_field"]
	assert.Equal(t, v, "1234abcd")
}
