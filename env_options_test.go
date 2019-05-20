package main_test

import (
	"os"
	"testing"

	proxy "github.com/pusher/oauth2_proxy"
	"github.com/stretchr/testify/assert"
)

type EnvTest struct {
	TestField string `cfg:"target_field" env:"TEST_ENV_FIELD"`
	EnvTestEmbed
}

type EnvTestEmbed struct {
	TestFieldEmbed string `cfg:"target_field_embed" env:"TEST_ENV_FIELD_EMBED"`
}

func TestLoadEnvForStruct(t *testing.T) {

	cfg := make(proxy.EnvOptions)
	cfg.LoadEnvForStruct(&EnvTest{})

	_, ok := cfg["target_field"]
	assert.Equal(t, ok, false)

	os.Setenv("TEST_ENV_FIELD", "1234abcd")
	cfg.LoadEnvForStruct(&EnvTest{})
	v := cfg["target_field"]
	assert.Equal(t, v, "1234abcd")
}

func TestLoadEnvForStructWithEmbeddedFields(t *testing.T) {

	cfg := make(proxy.EnvOptions)
	cfg.LoadEnvForStruct(&EnvTest{})

	_, ok := cfg["target_field_embed"]
	assert.Equal(t, ok, false)

	os.Setenv("TEST_ENV_FIELD_EMBED", "1234abcd")
	cfg.LoadEnvForStruct(&EnvTest{})
	v := cfg["target_field_embed"]
	assert.Equal(t, v, "1234abcd")
}
