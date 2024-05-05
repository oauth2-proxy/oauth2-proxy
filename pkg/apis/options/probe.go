package options

type ProbeOptions struct {
	PingPath              string `yaml:"pingPath,omitempty"`
	PingUserAgent         string `yaml:"pingUserAgent,omitempty"`
	ReadyPath             string `yaml:"readyPath,omitempty"`
	LegacyGCPHealthChecks bool   `yaml:"legacyGCPHealthChecks,omitempty"`
}

func probeOptionsDefaults() ProbeOptions {
	return ProbeOptions{
		PingPath:              "/ping",
		PingUserAgent:         "",
		ReadyPath:             "/ready",
		LegacyGCPHealthChecks: false,
	}
}
