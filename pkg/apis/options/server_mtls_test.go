package options

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLegacyClientCAConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name             string
		appCA, metricsCA string
	}{
		{"disabled", "", ""}, {"app only", "app-ca.pem", ""},
		{"metrics only", "", "metrics-ca.pem"}, {"independent", "app-ca.pem", "metrics-ca.pem"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			legacy := LegacyServer{HTTPAddress: "127.0.0.1:4180", HTTPSAddress: ":443", MetricsSecureAddress: ":9443", TLSClientCAFile: tc.appCA, MetricsTLSClientCAFile: tc.metricsCA}
			app, metrics := legacy.convert()
			if tc.appCA == "" {
				require.Nil(t, app.TLS)
				require.Empty(t, app.SecureBindAddress)
			} else {
				require.Equal(t, tc.appCA, app.TLS.ClientCA.FromFile)
				require.Empty(t, app.BindAddress)
				require.Equal(t, ":443", app.SecureBindAddress)
			}
			if tc.metricsCA == "" {
				require.Nil(t, metrics.TLS)
			} else {
				require.Equal(t, tc.metricsCA, metrics.TLS.ClientCA.FromFile)
			}
		})
	}
}
