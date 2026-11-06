package options

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoogleGroupMembershipConcurrency(t *testing.T) {
	for _, tc := range []struct {
		name, config, env, flag string
		want                    int
	}{
		{name: "default", want: 5},
		{name: "config", config: "2", want: 2},
		{name: "environment", config: "2", env: "3", want: 3},
		{name: "flag", config: "2", env: "3", flag: "10", want: 10},
		{name: "zero", env: "0", want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OAUTH2_PROXY_GOOGLE_GROUP_MEMBERSHIP_CONCURRENCY", tc.env)
			flags := NewLegacyFlagSet()
			require.Equal(t, "5", flags.Lookup("google-group-membership-concurrency").DefValue)
			if tc.flag != "" {
				require.NoError(t, flags.Set("google-group-membership-concurrency", tc.flag))
			}
			path := ""
			if tc.config != "" {
				path = filepath.Join(t.TempDir(), "config.toml")
				require.NoError(t, os.WriteFile(path, []byte("google_group_membership_concurrency = "+tc.config), 0600))
			}
			legacy := NewLegacyOptions()
			require.NoError(t, Load(path, flags, legacy))
			opts, err := legacy.ToOptions()
			require.NoError(t, err)
			require.NotNil(t, opts.Providers[0].GoogleConfig.GroupMembershipConcurrency)
			assert.Equal(t, tc.want, *opts.Providers[0].GoogleConfig.GroupMembershipConcurrency)
		})
	}
	t.Run("invalid environment", func(t *testing.T) {
		t.Setenv("OAUTH2_PROXY_GOOGLE_GROUP_MEMBERSHIP_CONCURRENCY", "invalid")
		require.Error(t, Load("", NewLegacyFlagSet(), NewLegacyOptions()))
	})
}

func TestGoogleGroupMembershipConcurrencyYAML(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        int
	}{
		{name: "default", want: 5},
		{name: "sequential", value: "groupMembershipConcurrency: 1", want: 1},
		{name: "maximum", value: "groupMembershipConcurrency: 10", want: 10},
		{name: "zero", value: "groupMembershipConcurrency: 0", want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			content := fmt.Sprintf("providers:\n- id: google\n  provider: google\n  googleConfig:\n    %s\n", tc.value)
			require.NoError(t, os.WriteFile(path, []byte(content), 0600))
			var opts AlphaOptions
			require.NoError(t, LoadYAML(path, &opts))
			opts.Providers.EnsureDefaults()
			assert.Equal(t, tc.want, *opts.Providers[0].GoogleConfig.GroupMembershipConcurrency)
		})
	}
}
