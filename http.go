package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// Server represents an HTTP server
type Server struct {
	Handler http.Handler
	Opts    *options.Options
	stop    chan struct{} // channel for waiting shutdown
}

// ListenAndServe will serve traffic on HTTP or HTTPS depending on TLS options
func (s *Server) ListenAndServe() {
	if s.Opts.TLSKeyFile != "" || s.Opts.TLSCertFile != "" {
		s.ServeHTTPS()
	} else {
		s.ServeHTTP()
	}
}

// ServeHTTP constructs a net.Listener and starts handling HTTP requests
func (s *Server) ServeHTTP() {
	HTTPAddress := s.Opts.HTTPAddress
	var scheme string

	i := strings.Index(HTTPAddress, "://")
	if i > -1 {
		scheme = HTTPAddress[0:i]
	}

	var networkType string
	switch scheme {
	case "", "http":
		networkType = "tcp"
	default:
		networkType = scheme
	}

	slice := strings.SplitN(HTTPAddress, "//", 2)
	listenAddr := slice[len(slice)-1]

	listener, err := net.Listen(networkType, listenAddr)
	if err != nil {
		logger.Fatalf("FATAL: listen (%s, %s) failed - %s", networkType, listenAddr, err)
	}
	logger.Printf("HTTP: listening on %s", listenAddr)
	s.serve(listener)
	logger.Printf("HTTP: closing %s", listener.Addr())
}

// ServeHTTPS constructs a net.Listener and starts handling HTTPS requests
func (s *Server) ServeHTTPS() {
	addr := s.Opts.HTTPSAddress
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}
	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(s.Opts.TLSCertFile, s.Opts.TLSKeyFile)
	if err != nil {
		logger.Fatalf("FATAL: loading tls config (%s, %s) failed - %s", s.Opts.TLSCertFile, s.Opts.TLSKeyFile, err)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Fatalf("FATAL: listen (%s) failed - %s", addr, err)
	}
	logger.Printf("HTTPS: listening on %s", ln.Addr())

	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)
	s.serve(tlsListener)
	logger.Printf("HTTPS: closing %s", tlsListener.Addr())
}

func (s *Server) serve(listener net.Listener) {
	srv := &http.Server{Handler: s.Handler}

	// See https://golang.org/pkg/net/http/#Server.Shutdown
	idleConnsClosed := make(chan struct{})
	go func() {
		<-s.stop // wait notification for stopping server

		// We received an interrupt signal, shut down.
		if err := srv.Shutdown(context.Background()); err != nil {
			// Error from closing listeners, or context timeout:
			logger.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	err := srv.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Errorf("ERROR: http.Serve() - %s", err)
	}
	<-idleConnsClosed
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	err = tc.SetKeepAlive(true)
	if err != nil {
		logger.Printf("Error setting Keep-Alive: %v", err)
	}
	err = tc.SetKeepAlivePeriod(3 * time.Minute)
	if err != nil {
		logger.Printf("Error setting Keep-Alive period: %v", err)
	}
	return tc, nil
}
