//go:build windows
// +build windows

package http

import (
	"fmt"
	"strings"
)

func (s *server) checkSystemdSocketSupport(opts Opts) error {
	if strings.HasPrefix(strings.ToLower(opts.BindAddress), "fd:") {
		listenAddr := opts.BindAddress[3:]
		return fmt.Errorf("listen (file, %s) failed: systemd sockets are not supported on windows", listenAddr)
	}
	return nil
}
