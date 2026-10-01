package version

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveVersion(t *testing.T) {
	testCases := []struct {
		name           string
		ldflagsVersion string
		buildInfo      *debug.BuildInfo
		buildInfoOK    bool
		expected       string
	}{
		{
			name:           "ldflags version takes precedence over build info",
			ldflagsVersion: "v7.15.3",
			buildInfo:      &debug.BuildInfo{Main: debug.Module{Version: "v7.15.0"}},
			buildInfoOK:    true,
			expected:       "v7.15.3",
		},
		{
			name:           "falls back to build info version when undefined",
			ldflagsVersion: "undefined",
			buildInfo:      &debug.BuildInfo{Main: debug.Module{Version: "v7.15.3"}},
			buildInfoOK:    true,
			expected:       "v7.15.3",
		},
		{
			name:           "keeps undefined when build info is unavailable",
			ldflagsVersion: "undefined",
			buildInfo:      nil,
			buildInfoOK:    false,
			expected:       "undefined",
		},
		{
			name:           "keeps undefined for a (devel) build info version",
			ldflagsVersion: "undefined",
			buildInfo:      &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}},
			buildInfoOK:    true,
			expected:       "undefined",
		},
		{
			name:           "keeps undefined for an empty build info version",
			ldflagsVersion: "undefined",
			buildInfo:      &debug.BuildInfo{Main: debug.Module{Version: ""}},
			buildInfoOK:    true,
			expected:       "undefined",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := resolveVersion(tc.ldflagsVersion, func() (*debug.BuildInfo, bool) {
				return tc.buildInfo, tc.buildInfoOK
			})
			assert.Equal(t, tc.expected, result)
		})
	}
}
