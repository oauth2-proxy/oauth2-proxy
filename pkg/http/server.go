package http

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options/util"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// Server represents an HTTP or HTTPS server.
type Server interface {
	// Start blocks and runs the server.
	Start(ctx context.Context) error
}

// Opts contains the information required to set up the server.
type Opts struct {
	// Handler is the http.Handler to be used to serve http pages by the server.
	Handler http.Handler

	// BindAddress is the address the HTTP server should listen on.
	BindAddress string

	// SecureBindAddress is the address the HTTPS server should listen on.
	SecureBindAddress string

	// TLS is the TLS configuration for the server.
	TLS *options.TLS

	// Let testing infrastructure circumvent parsing file descriptors
	fdFiles []*os.File
}

// NewServer creates a new Server from the options given.
func NewServer(opts Opts) (Server, error) {
	s := &server{
		handler: opts.Handler,
	}

	if len(opts.fdFiles) > 0 {
		s.fdFiles = opts.fdFiles
	}

	if err := s.setupListener(opts); err != nil {
		return nil, fmt.Errorf("error setting up listener: %v", err)
	}
	if err := s.setupTLSListener(opts); err != nil {
		return nil, fmt.Errorf("error setting up TLS listener: %v", err)
	}

	return s, nil
}

// server is an implementation of the Server interface.
type server struct {
	handler http.Handler

	listener    net.Listener
	tlsListener net.Listener

	// ensure activation.Files are called once
	fdFiles []*os.File
}

// setupListener sets the server listener if the HTTP server is enabled.
// The HTTP server can be disabled by setting the BindAddress to "-" or by
// leaving it empty.
func (s *server) setupListener(opts Opts) error {
	if opts.BindAddress == "" || opts.BindAddress == "-" {
		// No HTTP listener required
		return nil
	}

	// Use fd: as a prefix for systemd socket activation, it's generic
	// enough and short.
	// The most common usage would be --http-address fd:3.
	// This causes oauth2-proxy to just assume that the third fd passed
	// to the program is indeed a net.Listener and starts using it
	// without setting up a new listener.
	if strings.HasPrefix(strings.ToLower(opts.BindAddress), "fd:") {
		return s.checkSystemdSocketSupport(opts)
	}

	networkType := getNetworkScheme(opts.BindAddress)
	listenAddr := getListenAddress(opts.BindAddress)

	listener, err := net.Listen(networkType, listenAddr)
	if err != nil {
		return fmt.Errorf("listen (%s, %s) failed: %w", networkType, listenAddr, err)
	}
	s.listener = listener

	return nil
}

func parseCipherSuites(names []string) ([]uint16, error) {
	cipherNameMap := make(map[string]uint16)

	for _, cipherSuite := range tls.CipherSuites() {
		cipherNameMap[cipherSuite.Name] = cipherSuite.ID
	}
	for _, cipherSuite := range tls.InsecureCipherSuites() {
		cipherNameMap[cipherSuite.Name] = cipherSuite.ID
	}

	result := make([]uint16, len(names))
	for i, name := range names {
		id, present := cipherNameMap[name]
		if !present {
			return nil, fmt.Errorf("unknown TLS cipher suite name specified %q", name)
		}
		result[i] = id
	}
	return result, nil
}

// setupTLSListener sets the server TLS listener if the HTTPS server is enabled.
// The HTTPS server can be disabled by setting the SecureBindAddress to "-" or by
// leaving it empty.
func (s *server) setupTLSListener(opts Opts) error {
	if opts.SecureBindAddress == "" || opts.SecureBindAddress == "-" {
		// No HTTPS listener required
		return nil
	}

	config := &tls.Config{
		MinVersion: tls.VersionTLS12, // default, override below
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"http/1.1"},
	}
	if opts.TLS == nil {
		return errors.New("no TLS config provided")
	}

	l, err := getCertificateLoader(opts.TLS)
	if err != nil {
		return fmt.Errorf("could not load certificate: %v", err)
	}
	config.GetCertificate = l.GetCertificate

	if len(opts.TLS.CipherSuites) > 0 {
		cipherSuites, err := parseCipherSuites(opts.TLS.CipherSuites)
		if err != nil {
			return fmt.Errorf("could not parse cipher suites: %v", err)
		}
		config.CipherSuites = cipherSuites
	}

	if len(opts.TLS.MinVersion) > 0 {
		switch opts.TLS.MinVersion {
		case "TLS1.2":
			config.MinVersion = tls.VersionTLS12
		case "TLS1.3":
			config.MinVersion = tls.VersionTLS13
		default:
			return errors.New("unknown TLS MinVersion config provided")
		}
	}

	listenAddr := getListenAddress(opts.SecureBindAddress)

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen (%s) failed: %v", listenAddr, err)
	}

	ka := tcpKeepAliveListener{listener.(*net.TCPListener)}
	s.tlsListener = reloadableTLSListener{
		Listener: tls.NewListener(ka, config),
		loader:   l,
	}
	return nil
}

// Start starts the HTTP and HTTPS server if applicable.
// It will block until the context is cancelled.
// If any errors occur, only the first error will be returned.
func (s *server) Start(ctx context.Context) error {
	g, groupCtx := errgroup.WithContext(ctx)

	if s.listener != nil {
		g.Go(func() error {
			if err := s.startServer(groupCtx, s.listener); err != nil {
				return fmt.Errorf("error starting insecure server: %v", err)
			}
			return nil
		})
	}

	if s.tlsListener != nil {
		rl := s.tlsListener.(reloadableTLSListener)
		ch := make(chan os.Signal, 1)

		g.Go(func() error {
			for {
				select {
				case <-ch:
					if err := rl.Reload(); err != nil {
						logger.Errorf("Error reloading TLS certificate: %v", err)
					}
				case <-ctx.Done():
					return nil
				}
			}
		})
		signal.Notify(ch, syscall.SIGHUP)

		g.Go(func() error {
			if err := s.startServer(groupCtx, s.tlsListener); err != nil {
				return fmt.Errorf("error starting secure server: %v", err)
			}
			return nil
		})
	}

	return g.Wait()
}

// startServer creates and starts a new server with the given listener.
// When the given context is cancelled the server will be shutdown.
// If any errors occur, only the first error will be returned.
func (s *server) startServer(ctx context.Context, listener net.Listener) error {
	srv := &http.Server{Handler: s.handler, ReadHeaderTimeout: time.Minute}
	g, groupCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		<-groupCtx.Done()

		if err := srv.Shutdown(context.Background()); err != nil {
			return fmt.Errorf("error shutting down server: %v", err)
		}
		return nil
	})

	g.Go(func() error {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("could not start server: %v", err)
		}
		return nil
	})

	return g.Wait()
}

// getNetworkScheme gets the scheme for the HTTP server.
func getNetworkScheme(addr string) string {
	var scheme string
	i := strings.Index(addr, "://")
	if i > -1 {
		scheme = addr[0:i]
	}

	switch scheme {
	case "", "http":
		return "tcp"
	default:
		return scheme
	}
}

// getListenAddress gets the address for the HTTP server.
func getListenAddress(addr string) string {
	slice := strings.SplitN(addr, "//", 2)
	return slice[len(slice)-1]
}

type tlsLoader struct {
	*options.TLS

	mu   sync.Mutex
	cert *tls.Certificate
}

func (t *tlsLoader) LoadCert() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	keyData, err := getSecretValue(t.Key)
	if err != nil {
		return fmt.Errorf("could not load key data: %v", err)
	}

	certData, err := getSecretValue(t.Cert)
	if err != nil {
		return fmt.Errorf("could not load cert data: %v", err)
	}

	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return fmt.Errorf("could not parse certificate data: %v", err)
	}

	t.cert = &cert
	return nil
}

func (t *tlsLoader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if t.cert == nil {
		return nil, fmt.Errorf("no certificate")
	}

	return t.cert, nil
}

func getCertificateLoader(opts *options.TLS) (*tlsLoader, error) {
	l := &tlsLoader{
		TLS: opts,
	}

	if err := l.LoadCert(); err != nil {
		return nil, err
	}

	return l, nil
}

type reloadableTLSListener struct {
	net.Listener
	loader *tlsLoader
}

func (rl reloadableTLSListener) Reload() error {
	return rl.loader.LoadCert()
}

// getSecretValue wraps util.GetSecretValue so that we can return an error if no
// source is provided.
func getSecretValue(src *options.SecretSource) ([]byte, error) {
	if src == nil {
		return nil, errors.New("no configuration provided")
	}
	return util.GetSecretValue(src)
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by so that dead TCP connections (e.g. closing laptop
// mid-download) eventually go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

// Accept implements the TCPListener interface.
// It sets the keep alive period to 3 minutes for each connection.
func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	err = tc.SetKeepAlive(true)
	if err != nil {
		logger.Errorf("Error setting Keep-Alive: %v", err)
	}
	err = tc.SetKeepAlivePeriod(3 * time.Minute)
	if err != nil {
		logger.Printf("Error setting Keep-Alive period: %v", err)
	}
	return tc, nil
}
