//go:build !windows
// +build !windows

package http

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/coreos/go-systemd/activation"
)

// listenFdsStart corresponds to `SD_LISTEN_FDS_START`.
// Since the 3 first file descriptors in every linux process is
// stdin, stdout and stderr. The first usable file descriptor is 3.
// systemd-socket-activate will always assume that the first socket will be
// 3 and the rest follow.
const (
	listenFdsStart = 3
)

// convert a string filedescriptor to an actual listener
func (s *server) fdToListener(bindAddress string) (net.Listener, error) {
	fd, err := strconv.Atoi(bindAddress)
	if err != nil {
		return nil, errors.New("listen failed: fd with name is not implemented yet")
	}
	fdIndex := fd - listenFdsStart

	if len(s.fdFiles) == 0 {
		s.fdFiles = activation.Files(true)
	}

	l := len(s.fdFiles)

	if fdIndex < 0 || fdIndex >= l || l == 0 {
		return nil, errors.New("listen failed: fd outside of range of available file descriptors")
	}

	return net.FileListener(s.fdFiles[fdIndex])
}

func (s *server) checkSystemdSocketSupport(opts Opts) error {
	listenAddr := opts.BindAddress[3:]
	listener, err := s.fdToListener(listenAddr)
	if err != nil {
		err = fmt.Errorf("listen (file, %s) failed: %w", listenAddr, err)
		return err
	}

	s.listener = listener
	return nil
}
