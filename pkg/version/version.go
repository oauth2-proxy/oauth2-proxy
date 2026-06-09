package version

import "runtime/debug"

// VERSION contains version information. It is set at build time via
// -ldflags "-X github.com/oauth2-proxy/oauth2-proxy/v7/pkg/version.VERSION=<version>".
// When the binary is built without those flags (for example via
// `go install github.com/oauth2-proxy/oauth2-proxy/v7@latest`), it falls back
// to the module version recorded in the build info so that `--version` still
// reports a meaningful value instead of "undefined".
var VERSION = "undefined"

func init() {
	VERSION = resolveVersion(VERSION, debug.ReadBuildInfo)
}

// resolveVersion returns ldflagsVersion when it has been explicitly set at
// build time. Otherwise it derives the version from the module build info,
// allowing `go install`-ed binaries to report a meaningful version.
func resolveVersion(ldflagsVersion string, readBuildInfo func() (*debug.BuildInfo, bool)) string {
	if ldflagsVersion != "" && ldflagsVersion != "undefined" {
		return ldflagsVersion
	}
	if info, ok := readBuildInfo(); ok && info != nil {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return ldflagsVersion
}
