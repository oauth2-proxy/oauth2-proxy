package version

import (
	"runtime/debug"
	"testing"
)

func TestNormalizeModuleVersion(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"(devel)", ""},
		{"v7.15.3", "7.15.3"},
		{"7.15.3", "7.15.3"},
	}
	for _, tt := range tests {
		if got := normalizeModuleVersion(tt.in); got != tt.want {
			t.Errorf("normalizeModuleVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestVersionFromBuildInfo(t *testing.T) {
	got := versionFromBuildInfo(&debug.BuildInfo{
		Main: debug.Module{Path: "github.com/oauth2-proxy/oauth2-proxy/v7", Version: "v7.15.3"},
	})
	if got != "7.15.3" {
		t.Fatalf("versionFromBuildInfo(main)=%q, want 7.15.3", got)
	}

	got = versionFromBuildInfo(&debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Deps: []*debug.Module{{
			Path:    "github.com/oauth2-proxy/oauth2-proxy/v7",
			Version: "v7.14.0",
		}},
	})
	if got != "7.14.0" {
		t.Fatalf("versionFromBuildInfo(deps)=%q, want 7.14.0", got)
	}

	if got := versionFromBuildInfo(&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}); got != "" {
		t.Fatalf("versionFromBuildInfo(devel)=%q, want empty", got)
	}
}
