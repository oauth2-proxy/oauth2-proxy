package options

type ProbeOptions struct {
	PingPath      string `json:"pingPath,omitempty"`
	PingUserAgent string `json:"pingUserAgent,omitempty"`
	ReadyPath     string `json:"readyPath,omitempty"`
}

func probeOptionsDefaults() ProbeOptions {
	return ProbeOptions{
		PingPath:      "/ping",
		PingUserAgent: "",
		ReadyPath:     "/ready",
	}
}
