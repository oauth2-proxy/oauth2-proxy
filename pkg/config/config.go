package config

type Config struct {
	maskSessionPII bool
}

func New() *Config {
	return &Config{
		maskSessionPII: false,
	}
}

var std = New()

func (c *Config) SetMaskSessionPII(b bool) {
	c.maskSessionPII = b
}

func SetMaskSessionPII(b bool) {
	std.SetMaskSessionPII(b)
}

func GetMaskSessionPII() bool {
	return std.maskSessionPII
}
