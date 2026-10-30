package version

import (
	"runtime/debug"
	"strings"
)

// VERSION contains version information. Release and `make build` binaries set
// this via -ldflags. When unset (e.g. `go install …@latest`), init() fills it
// from the module version embedded by the Go toolchain.
var VERSION = "undefined"

func init() {
	if VERSION != "" && VERSION != "undefined" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if v := versionFromBuildInfo(info); v != "" {
		VERSION = v
	}
}

func versionFromBuildInfo(info *debug.BuildInfo) string {
	if info == nil {
		return ""
	}
	if v := normalizeModuleVersion(info.Main.Version); v != "" {
		return v
	}
	// Dependents embedding oauth2-proxy may list it as a module dependency.
	for _, dep := range info.Deps {
		if dep == nil {
			continue
		}
		if dep.Path == "github.com/oauth2-proxy/oauth2-proxy/v7" {
			if v := normalizeModuleVersion(dep.Version); v != "" {
				return v
			}
		}
	}
	return ""
}

func normalizeModuleVersion(v string) string {
	if v == "" || v == "(devel)" {
		return ""
	}
	return strings.TrimPrefix(v, "v")
}
