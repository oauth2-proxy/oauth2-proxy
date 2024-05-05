package options

import "github.com/spf13/pflag"

type LegacyProbeOptions struct {
	PingPath        string `flag:"ping-path" cfg:"ping_path"`
	PingUserAgent   string `flag:"ping-user-agent" cfg:"ping_user_agent"`
	ReadyPath       string `flag:"ready-path" cfg:"ready_path"`
	GCPHealthChecks bool   `flag:"gcp-healthchecks" cfg:"gcp_healthchecks"`
}

func legacyProbeOptionsFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("probe", pflag.ExitOnError)

	flagSet.String("ping-path", "/ping", "the ping endpoint that can be used for basic health checks")
	flagSet.String("ping-user-agent", "", "special User-Agent that will be used for basic health checks")
	flagSet.String("ready-path", "/ready", "the ready endpoint that can be used for deep health checks")
	flagSet.Bool("gcp-healthchecks", false, "Enable GCP/GKE healthcheck endpoints")

	return flagSet
}

func (l *LegacyProbeOptions) convert() ProbeOptions {
	return ProbeOptions{
		PingPath:              l.PingPath,
		PingUserAgent:         l.PingUserAgent,
		ReadyPath:             l.ReadyPath,
		LegacyGCPHealthChecks: l.GCPHealthChecks,
	}
}
