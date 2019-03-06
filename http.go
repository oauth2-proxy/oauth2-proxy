package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Server represents an HTTP server
type Server struct {
	Handler http.Handler
	Opts    *Options

	logger *zap.Logger
}

// ListenAndServe will serve traffic on HTTP or HTTPS depending on TLS options
func (s *Server) ListenAndServe() {
	config := zap.NewProductionConfig()
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.OutputPaths = []string{s.Opts.HTTPLogPath}
	s.logger, _ = config.Build()
	defer s.logger.Sync()
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
		s.logger.Fatal("Failed to listen",
			zap.String("networkType", networkType),
			zap.String("listenAddress", listenAddr),
			zap.String("error", err.Error()))
	}
	s.logger.Info("HTTP Listening",
		zap.String("listenAddress", listenAddr))

	server := &http.Server{Handler: s.Handler}
	err = server.Serve(listener)
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		s.logger.Error("Error while serving with http.Serve()",
			zap.String("error", err.Error()))
	}

	s.logger.Info("Closing HTTP Server",
		zap.String("listeningAddress", listener.Addr().String()))
}

// ServeHTTPS constructs a net.Listener and starts handling HTTPS requests
func (s *Server) ServeHTTPS() {
	addr := s.Opts.HTTPSAddress
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	}
	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(s.Opts.TLSCertFile, s.Opts.TLSKeyFile)
	if err != nil {
		s.logger.Fatal("Error loading TLS configuration",
			zap.String("tlsCertFile", s.Opts.TLSCertFile),
			zap.String("tlsKeyFile", s.Opts.TLSKeyFile),
			zap.String("error", err.Error()))
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.logger.Fatal("Error listening",
			zap.String("listenAddress", addr),
			zap.String("error", err.Error()))
	}
	s.logger.Info("Listening HTTPS",
		zap.String("listeningAddress", ln.Addr().String()))

	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, config)
	srv := &http.Server{Handler: s.Handler}
	err = srv.Serve(tlsListener)

	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		s.logger.Error("Error while serving https.Serve()",
			zap.String("error", err.Error()))
	}
	s.logger.Info("Closing HTTPS servrer",
		zap.String("listeningAddress", tlsListener.Addr().String()))
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
