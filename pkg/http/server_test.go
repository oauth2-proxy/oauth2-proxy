package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gleak"
)

const hello = "Hello World!"

var _ = Describe("Server", func() {

	handler := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte(hello))
	})
	Context("NewServer", func() {
		type newServerTableInput struct {
			opts               Opts
			expectedErr        error
			expectHTTPListener bool
			expectTLSListener  bool
			fdAddr             string
			ipv6               bool
		}

		DescribeTable("When creating the new server from the options", func(in *newServerTableInput) {
			if in.ipv6 {
				skipDevContainer()
			}

			if in.fdAddr != "" {
				l, err := net.Listen("tcp", in.fdAddr)
				Expect(err).ToNot(HaveOccurred())
				f, err := l.(*net.TCPListener).File()
				Expect(err).ToNot(HaveOccurred())
				in.opts.fdFiles = []*os.File{f}
			}

			srv, err := NewServer(in.opts)
			if in.expectedErr != nil {
				Expect(err).To(MatchError(ContainSubstring(in.expectedErr.Error())))
				Expect(srv).To(BeNil())
				return
			}

			Expect(err).ToNot(HaveOccurred())

			s, ok := srv.(*server)
			Expect(ok).To(BeTrue())

			Expect(s.listener != nil).To(Equal(in.expectHTTPListener))
			if in.expectHTTPListener {
				Expect(s.listener.Close()).To(Succeed())
			}
			Expect(s.tlsListener != nil).To(Equal(in.expectTLSListener))
			if in.expectTLSListener {
				Expect(s.tlsListener.Close()).To(Succeed())
			}
		},
			Entry("with a valid non-lowercase fd IPv4 bind address", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "Fd:3",
				},
				expectedErr:        nil,
				expectHTTPListener: true,
				expectTLSListener:  false,
				fdAddr:             "127.0.0.1:0",
			}),
			Entry("with a valid fd IPv4 bind address", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "fd:3",
				},
				expectedErr:        nil,
				expectHTTPListener: true,
				expectTLSListener:  false,
				fdAddr:             "127.0.0.1:0",
			}),
			Entry("with a invalid fd named bind address", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "fd:hello",
				},
				expectedErr:        fmt.Errorf("error setting up listener: listen (file, %s) failed: listen failed: fd with name is not implemented yet", "hello"),
				expectHTTPListener: true,
				expectTLSListener:  false,
				fdAddr:             "127.0.0.1:0",
			}),
			Entry("with a invalid fd IPv4 bind address", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "fd:4",
				},
				expectedErr:        fmt.Errorf("error setting up listener: listen (file, %d) failed: listen failed: fd outside of range of available file descriptors", 4),
				expectHTTPListener: true,
				expectTLSListener:  false,
				fdAddr:             "127.0.0.1:0",
			}),
			Entry("with an ipv4 valid http bind address", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "127.0.0.1:0",
				},
				expectedErr:        nil,
				expectHTTPListener: true,
				expectTLSListener:  false,
			}),
			Entry("with an ipv4 valid https bind address, with no TLS config", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
				},
				expectedErr:        errors.New("error setting up TLS listener: no TLS config provided"),
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("with an ipv4 valid https bind address, and valid TLS config", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key:  &ipv4KeyDataSource,
						Cert: &ipv4CertDataSource,
					},
				},
				expectedErr:        nil,
				expectHTTPListener: false,
				expectTLSListener:  true,
			}),
			Entry("with a both a fd valid http and ipv4 valid https bind address, and valid TLS config", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					BindAddress:       "fd:3",
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key:  &ipv4KeyDataSource,
						Cert: &ipv4CertDataSource,
					},
				},
				expectedErr:        nil,
				expectHTTPListener: true,
				expectTLSListener:  true,
				fdAddr:             "127.0.0.1:0",
			}),
			Entry("with a both a ipv4 valid http and ipv4 valid https bind address, and valid TLS config", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					BindAddress:       "127.0.0.1:0",
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key:  &ipv4KeyDataSource,
						Cert: &ipv4CertDataSource,
					},
				},
				expectedErr:        nil,
				expectHTTPListener: true,
				expectTLSListener:  true,
			}),
			Entry("with a \"-\" for the bind address", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "-",
				},
				expectedErr:        nil,
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("with a \"-\" for the secure bind address", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "-",
				},
				expectedErr:        nil,
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("with an ipv4 invalid bind address scheme", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "invalid://127.0.0.1:0",
				},
				expectedErr:        errors.New("error setting up listener: listen (invalid, 127.0.0.1:0) failed: listen invalid: unknown network invalid"),
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("with an ipv4 invalid secure bind address scheme", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "invalid://127.0.0.1:0",
					TLS: &options.TLS{
						Key:  &ipv4KeyDataSource,
						Cert: &ipv4CertDataSource,
					},
				},
				expectedErr:        nil,
				expectHTTPListener: false,
				expectTLSListener:  true,
			}),
			Entry("with an ipv4 invalid bind address port", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "127.0.0.1:a",
				},
				expectedErr:        errors.New("error setting up listener: listen (tcp, 127.0.0.1:a) failed: listen tcp: "),
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("with an ipv4 invalid secure bind address port", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:a",
					TLS: &options.TLS{
						Key:  &ipv4KeyDataSource,
						Cert: &ipv4CertDataSource,
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: listen (127.0.0.1:a) failed: listen tcp: "),
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("with an ipv4 invalid TLS key", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key: &options.SecretSource{
							Value: []byte("invalid"),
						},
						Cert: &ipv4CertDataSource,
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: could not load certificate: could not parse certificate data: tls: failed to find any PEM data in key input"),
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("with an ipv4 invalid TLS cert", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key: &ipv4KeyDataSource,
						Cert: &options.SecretSource{
							Value: []byte("invalid"),
						},
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: could not load certificate: could not parse certificate data: tls: failed to find any PEM data in certificate input"),
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("with an ipv4 address, with no TLS key", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Cert: &ipv4CertDataSource,
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: could not load certificate: could not load key data: no configuration provided"),
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("with an ipv4 address, with no TLS cert", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key: &ipv4KeyDataSource,
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: could not load certificate: could not load cert data: no configuration provided"),
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("when the ipv4 bind address is prefixed with the http scheme", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "http://127.0.0.1:0",
				},
				expectedErr:        nil,
				expectHTTPListener: true,
				expectTLSListener:  false,
			}),
			Entry("when the ipv4 secure bind address is prefixed with the https scheme", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "https://127.0.0.1:0",
					TLS: &options.TLS{
						Key:  &ipv4KeyDataSource,
						Cert: &ipv4CertDataSource,
					},
				},
				expectedErr:        nil,
				expectHTTPListener: false,
				expectTLSListener:  true,
			}),
			Entry("with an ipv4 valid https bind address, and valid TLS config with MinVersion", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key:        &ipv4KeyDataSource,
						Cert:       &ipv4CertDataSource,
						MinVersion: "TLS1.3",
					},
				},
				expectedErr:        nil,
				expectHTTPListener: false,
				expectTLSListener:  true,
			}),
			Entry("with an ipv4 valid https bind address, and invalid TLS config with unknown MinVersion", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key:        &ipv4KeyDataSource,
						Cert:       &ipv4CertDataSource,
						MinVersion: "TLS1.42",
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: unknown TLS MinVersion config provided"),
				expectHTTPListener: false,
				expectTLSListener:  true,
			}),
			Entry("with an ipv4 valid https bind address, and valid TLS config with CipherSuites", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key:  &ipv4KeyDataSource,
						Cert: &ipv4CertDataSource,
						CipherSuites: []string{
							"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
							"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						},
					},
				},
				expectedErr:        nil,
				expectHTTPListener: false,
				expectTLSListener:  true,
			}),
			Entry("with an ipv4 valid https bind address, and invalid TLS config with unknown CipherSuites", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key:  &ipv4KeyDataSource,
						Cert: &ipv4CertDataSource,
						CipherSuites: []string{
							"TLS_RSA_WITH_RC4_64_SHA",
							"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						},
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: could not parse cipher suites: unknown TLS cipher suite name specified \"TLS_RSA_WITH_RC4_64_SHA\""),
				expectHTTPListener: false,
				expectTLSListener:  true,
			}),
			Entry("with valid fd IPv6 bind address", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "fd:3",
				},
				expectedErr:        nil,
				expectHTTPListener: true,
				expectTLSListener:  false,
				fdAddr:             "[::1]:0",
				ipv6:               true,
			}),
			Entry("with a invalid fd IPv6 bind address", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "fd:4",
				},
				expectedErr:        fmt.Errorf("error setting up listener: listen (file, %d) failed: listen failed: fd outside of range of available file descriptors", 4),
				expectHTTPListener: true,
				expectTLSListener:  false,
				fdAddr:             "[::1]:0",
			}),
			Entry("with an ipv6 valid http bind address", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "[::1]:0",
				},
				expectedErr:        nil,
				expectHTTPListener: true,
				expectTLSListener:  false,
				ipv6:               true,
			}),
			Entry("with an ipv6 valid https bind address, with no TLS config", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "[::1]:0",
				},
				expectedErr:        errors.New("error setting up TLS listener: no TLS config provided"),
				expectHTTPListener: false,
				expectTLSListener:  false,
				ipv6:               true,
			}),
			Entry("with an ipv6 valid https bind address, and valid TLS config", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "[::1]:0",
					TLS: &options.TLS{
						Key:  &ipv6KeyDataSource,
						Cert: &ipv6CertDataSource,
					},
				},
				expectedErr:        nil,
				expectHTTPListener: false,
				expectTLSListener:  true,
				ipv6:               true,
			}),
			Entry("with a both a fd valid http and ipv6 valid https bind address, and valid TLS config", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					BindAddress:       "fd:3",
					SecureBindAddress: "[::1]:0",
					TLS: &options.TLS{
						Key:  &ipv6KeyDataSource,
						Cert: &ipv6CertDataSource,
					},
				},
				expectedErr:        nil,
				expectHTTPListener: true,
				expectTLSListener:  true,
				fdAddr:             "[::1]:0",
				ipv6:               true,
			}),
			Entry("with a both a ipv6 valid http and ipv6 valid https bind address, and valid TLS config", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					BindAddress:       "[::1]:0",
					SecureBindAddress: "[::1]:0",
					TLS: &options.TLS{
						Key:  &ipv6KeyDataSource,
						Cert: &ipv6CertDataSource,
					},
				},
				expectedErr:        nil,
				expectHTTPListener: true,
				expectTLSListener:  true,
				ipv6:               true,
			}),
			Entry("with an ipv6 invalid bind address scheme", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "invalid://[::1]:0",
				},
				expectedErr:        errors.New("error setting up listener: listen (invalid, [::1]:0) failed: listen invalid: unknown network invalid"),
				expectHTTPListener: false,
				expectTLSListener:  false,
				ipv6:               true,
			}),
			Entry("with an ipv6 invalid secure bind address scheme", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "invalid://[::1]:0",
					TLS: &options.TLS{
						Key:  &ipv6KeyDataSource,
						Cert: &ipv6CertDataSource,
					},
				},
				expectedErr:        nil,
				expectHTTPListener: false,
				expectTLSListener:  true,
				ipv6:               true,
			}),
			Entry("with an ipv6 invalid bind address port", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "[::1]:a",
				},
				expectedErr:        errors.New("error setting up listener: listen (tcp, [::1]:a) failed: listen tcp: "),
				expectHTTPListener: false,
				expectTLSListener:  false,
				ipv6:               true,
			}),
			Entry("with an ipv6 invalid secure bind address port", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "[::1]:a",
					TLS: &options.TLS{
						Key:  &ipv6KeyDataSource,
						Cert: &ipv6CertDataSource,
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: listen ([::1]:a) failed: listen tcp: "),
				expectHTTPListener: false,
				expectTLSListener:  false,
				ipv6:               true,
			}),
			Entry("with an ipv6 invalid TLS key", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "[::1]:0",
					TLS: &options.TLS{
						Key: &options.SecretSource{
							Value: []byte("invalid"),
						},
						Cert: &ipv6CertDataSource,
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: could not load certificate: could not parse certificate data: tls: failed to find any PEM data in key input"),
				expectHTTPListener: false,
				expectTLSListener:  false,
				ipv6:               true,
			}),
			Entry("with an ipv6 invalid TLS cert", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "[::1]:0",
					TLS: &options.TLS{
						Key: &ipv6KeyDataSource,
						Cert: &options.SecretSource{
							Value: []byte("invalid"),
						},
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: could not load certificate: could not parse certificate data: tls: failed to find any PEM data in certificate input"),
				expectHTTPListener: false,
				expectTLSListener:  false,
				ipv6:               true,
			}),
			Entry("with an ipv6 address, with no TLS key", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "[::1]:0",
					TLS: &options.TLS{
						Cert: &ipv6CertDataSource,
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: could not load certificate: could not load key data: no configuration provided"),
				expectHTTPListener: false,
				expectTLSListener:  false,
				ipv6:               true,
			}),
			Entry("with an ipv6 address, with no TLS cert", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "[::1]:0",
					TLS: &options.TLS{
						Key: &ipv6KeyDataSource,
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: could not load certificate: could not load cert data: no configuration provided"),
				expectHTTPListener: false,
				expectTLSListener:  false,
				ipv6:               true,
			}),
			Entry("when the ipv6 bind address is prefixed with the http scheme", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "http://[::1]:0",
				},
				expectedErr:        nil,
				expectHTTPListener: true,
				expectTLSListener:  false,
				ipv6:               true,
			}),
			Entry("when the ipv6 secure bind address is prefixed with the https scheme", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "https://[::1]:0",
					TLS: &options.TLS{
						Key:  &ipv6KeyDataSource,
						Cert: &ipv6CertDataSource,
					},
				},
				expectedErr:        nil,
				expectHTTPListener: false,
				expectTLSListener:  true,
				ipv6:               true,
			}),
			Entry("with an ipv6 valid https bind address, and valid TLS config with MinVersion", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "[::1]:0",
					TLS: &options.TLS{
						Key:        &ipv6KeyDataSource,
						Cert:       &ipv6CertDataSource,
						MinVersion: "TLS1.3",
					},
				},
				expectedErr:        nil,
				expectHTTPListener: false,
				expectTLSListener:  true,
				ipv6:               true,
			}),
			Entry("with an ipv6 valid https bind address, and invalid TLS config with unknown MinVersion", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "[::1]:0",
					TLS: &options.TLS{
						Key:        &ipv6KeyDataSource,
						Cert:       &ipv6CertDataSource,
						MinVersion: "TLS1.42",
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: unknown TLS MinVersion config provided"),
				expectHTTPListener: false,
				expectTLSListener:  true,
				ipv6:               true,
			}),
			Entry("with an ipv6 valid https bind address, and valid TLS config with CipherSuites", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "[::1]:0",
					TLS: &options.TLS{
						Key:  &ipv4KeyDataSource,
						Cert: &ipv4CertDataSource,
						CipherSuites: []string{
							"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
							"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
						},
					},
				},
				expectedErr:        nil,
				expectHTTPListener: false,
				expectTLSListener:  true,
				ipv6:               true,
			}),
			Entry("with an ipv6 valid https bind address, and invalid TLS config with unknown CipherSuites", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "[::1]:0",
					TLS: &options.TLS{
						Key:  &ipv4KeyDataSource,
						Cert: &ipv4CertDataSource,
						CipherSuites: []string{
							"TLS_RSA_WITH_RC4_64_SHA",
							"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
						},
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: could not parse cipher suites: unknown TLS cipher suite name specified \"TLS_RSA_WITH_RC4_64_SHA\""),
				expectHTTPListener: false,
				expectTLSListener:  true,
				ipv6:               true,
			}),
		)
	})

	Context("Start", func() {
		var srv Server
		var ctx context.Context
		var cancel context.CancelFunc

		BeforeEach(func() {
			ctx, cancel = context.WithCancel(context.Background())
		})

		AfterEach(func() {
			cancel()
			Eventually(Goroutines).ShouldNot(HaveLeaked())

		})

		Context("with an fd ipv4 http server", func() {
			var listenAddr string

			BeforeEach(func() {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				Expect(err).ToNot(HaveOccurred())
				f, err := l.(*net.TCPListener).File()
				Expect(err).ToNot(HaveOccurred())

				srv, err = NewServer(Opts{
					Handler:     handler,
					BindAddress: "fd:3",
					fdFiles:     []*os.File{f},
				})
				Expect(err).ToNot(HaveOccurred())

				listenAddr = fmt.Sprintf("http://%s/", l.Addr().String())
			})

			It("Starts the server and serves the handler", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := httpGet(ctx, listenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := io.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Stops the server when the context is cancelled", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				_, err := httpGet(ctx, listenAddr)
				Expect(err).ToNot(HaveOccurred())

				cancel()

				Eventually(func() error {
					_, err := httpGet(ctx, listenAddr)
					return err
				}).Should(HaveOccurred())
			})
		})

		Context("with an ipv4 http server", func() {
			var listenAddr string

			BeforeEach(func() {
				var err error
				srv, err = NewServer(Opts{
					Handler:     handler,
					BindAddress: "127.0.0.1:0",
				})
				Expect(err).ToNot(HaveOccurred())

				s, ok := srv.(*server)
				Expect(ok).To(BeTrue())

				listenAddr = fmt.Sprintf("http://%s/", s.listener.Addr().String())
			})

			It("Starts the server and serves the handler", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := httpGet(ctx, listenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := io.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Stops the server when the context is cancelled", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				_, err := httpGet(ctx, listenAddr)
				Expect(err).ToNot(HaveOccurred())

				cancel()

				Eventually(func() error {
					_, err := httpGet(ctx, listenAddr)
					return err
				}).Should(HaveOccurred())
			})
		})

		Context("with an ipv4 https server", func() {
			var secureListenAddr string

			BeforeEach(func() {
				var err error
				srv, err = NewServer(Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key:  &ipv4KeyDataSource,
						Cert: &ipv4CertDataSource,
					},
				})
				Expect(err).ToNot(HaveOccurred())

				s, ok := srv.(*server)
				Expect(ok).To(BeTrue())

				secureListenAddr = fmt.Sprintf("https://%s/", s.tlsListener.Addr().String())
			})

			It("Starts the server and serves the handler", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := httpGet(ctx, secureListenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := io.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Stops the server when the context is cancelled", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				_, err := httpGet(ctx, secureListenAddr)
				Expect(err).ToNot(HaveOccurred())

				cancel()

				Eventually(func() error {
					_, err := httpGet(ctx, secureListenAddr)
					return err
				}).Should(HaveOccurred())
			})

			It("Serves the certificate provided", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := httpGet(ctx, secureListenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				Expect(resp.TLS.VerifiedChains).Should(HaveLen(1))
				Expect(resp.TLS.VerifiedChains[0]).Should(HaveLen(1))
				Expect(resp.TLS.VerifiedChains[0][0].Raw).Should(Equal(ipv4CertData))
			})
		})

		Context("with a fd ipv4 http and an ipv4 https server", func() {
			var listenAddr, secureListenAddr string

			BeforeEach(func() {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				Expect(err).ToNot(HaveOccurred())
				f, err := l.(*net.TCPListener).File()
				Expect(err).ToNot(HaveOccurred())

				srv, err = NewServer(Opts{
					Handler:           handler,
					BindAddress:       "fd:3",
					fdFiles:           []*os.File{f},
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key:  &ipv4KeyDataSource,
						Cert: &ipv4CertDataSource,
					},
				})
				Expect(err).ToNot(HaveOccurred())

				s, ok := srv.(*server)
				Expect(ok).To(BeTrue())

				listenAddr = fmt.Sprintf("http://%s/", l.Addr().String())
				secureListenAddr = fmt.Sprintf("https://%s/", s.tlsListener.Addr().String())
			})

			It("Starts the server and serves the handler on http", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := httpGet(ctx, listenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := io.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Starts the server and serves the handler on https", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := httpGet(ctx, secureListenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := io.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Stops both servers when the context is cancelled", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				_, err := httpGet(ctx, listenAddr)
				Expect(err).ToNot(HaveOccurred())
				_, err = httpGet(ctx, secureListenAddr)
				Expect(err).ToNot(HaveOccurred())

				cancel()

				Eventually(func() error {
					_, err := httpGet(ctx, listenAddr)
					return err
				}).Should(HaveOccurred())
				Eventually(func() error {
					_, err := httpGet(ctx, secureListenAddr)
					return err
				}).Should(HaveOccurred())
			})
		})

		Context("with both an ipv4 http and an ipv4 https server", func() {
			var listenAddr, secureListenAddr string

			BeforeEach(func() {
				var err error
				srv, err = NewServer(Opts{
					Handler:           handler,
					BindAddress:       "127.0.0.1:0",
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key:  &ipv4KeyDataSource,
						Cert: &ipv4CertDataSource,
					},
				})
				Expect(err).ToNot(HaveOccurred())

				s, ok := srv.(*server)
				Expect(ok).To(BeTrue())

				listenAddr = fmt.Sprintf("http://%s/", s.listener.Addr().String())
				secureListenAddr = fmt.Sprintf("https://%s/", s.tlsListener.Addr().String())
			})

			It("Starts the server and serves the handler on http", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := httpGet(ctx, listenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := io.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Starts the server and serves the handler on https", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := httpGet(ctx, secureListenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := io.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Stops both servers when the context is cancelled", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				_, err := httpGet(ctx, listenAddr)
				Expect(err).ToNot(HaveOccurred())
				_, err = httpGet(ctx, secureListenAddr)
				Expect(err).ToNot(HaveOccurred())

				cancel()

				Eventually(func() error {
					_, err := httpGet(ctx, listenAddr)
					return err
				}).Should(HaveOccurred())
				Eventually(func() error {
					_, err := httpGet(ctx, secureListenAddr)
					return err
				}).Should(HaveOccurred())
			})
		})

		Context("with an ipv6 http server", func() {
			var listenAddr string

			BeforeEach(func() {
				skipDevContainer()
				var err error
				srv, err = NewServer(Opts{
					Handler:     handler,
					BindAddress: "[::1]:0",
				})
				Expect(err).ToNot(HaveOccurred())

				s, ok := srv.(*server)
				Expect(ok).To(BeTrue())

				listenAddr = fmt.Sprintf("http://%s/", s.listener.Addr().String())
			})

			It("Starts the server and serves the handler", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := httpGet(ctx, listenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := io.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Stops the server when the context is cancelled", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				_, err := httpGet(ctx, listenAddr)
				Expect(err).ToNot(HaveOccurred())

				cancel()

				Eventually(func() error {
					_, err := httpGet(ctx, listenAddr)
					return err
				}).Should(HaveOccurred())
			})
		})

		Context("with an ipv6 https server", func() {
			var secureListenAddr string

			BeforeEach(func() {
				skipDevContainer()
				var err error
				srv, err = NewServer(Opts{
					Handler:           handler,
					SecureBindAddress: "[::1]:0",
					TLS: &options.TLS{
						Key:  &ipv6KeyDataSource,
						Cert: &ipv6CertDataSource,
					},
				})
				Expect(err).ToNot(HaveOccurred())

				s, ok := srv.(*server)
				Expect(ok).To(BeTrue())

				secureListenAddr = fmt.Sprintf("https://%s/", s.tlsListener.Addr().String())
			})

			It("Starts the server and serves the handler", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := httpGet(ctx, secureListenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := io.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Stops the server when the context is cancelled", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				_, err := httpGet(ctx, secureListenAddr)
				Expect(err).ToNot(HaveOccurred())

				cancel()

				Eventually(func() error {
					_, err := httpGet(ctx, secureListenAddr)
					return err
				}).Should(HaveOccurred())
			})

			It("Serves the certificate provided", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := httpGet(ctx, secureListenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				Expect(resp.TLS.VerifiedChains).Should(HaveLen(1))
				Expect(resp.TLS.VerifiedChains[0]).Should(HaveLen(1))
				Expect(resp.TLS.VerifiedChains[0][0].Raw).Should(Equal(ipv6CertData))
			})
		})

		Context("with an fd ipv6 http and an ipv6 https server", func() {
			var listenAddr, secureListenAddr string

			BeforeEach(func() {
				skipDevContainer()
				l, err := net.Listen("tcp", "[::1]:0")
				Expect(err).ToNot(HaveOccurred())
				f, err := l.(*net.TCPListener).File()
				Expect(err).ToNot(HaveOccurred())

				srv, err = NewServer(Opts{
					Handler:           handler,
					BindAddress:       "fd:3",
					fdFiles:           []*os.File{f},
					SecureBindAddress: "[::1]:0",
					TLS: &options.TLS{
						Key:  &ipv6KeyDataSource,
						Cert: &ipv6CertDataSource,
					},
				})
				Expect(err).ToNot(HaveOccurred())

				s, ok := srv.(*server)
				Expect(ok).To(BeTrue())

				listenAddr = fmt.Sprintf("http://%s/", l.Addr().String())
				secureListenAddr = fmt.Sprintf("https://%s/", s.tlsListener.Addr().String())
			})

			It("Starts the server and serves the handler on http", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := httpGet(ctx, listenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := io.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Starts the server and serves the handler on https", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := httpGet(ctx, secureListenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := io.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Stops both servers when the context is cancelled", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				_, err := httpGet(ctx, listenAddr)
				Expect(err).ToNot(HaveOccurred())
				_, err = httpGet(ctx, secureListenAddr)
				Expect(err).ToNot(HaveOccurred())

				cancel()

				Eventually(func() error {
					_, err := httpGet(ctx, listenAddr)
					return err
				}).Should(HaveOccurred())
				Eventually(func() error {
					_, err := httpGet(ctx, secureListenAddr)
					return err
				}).Should(HaveOccurred())
			})
		})

		Context("with both an ipv6 http and an ipv6 https server", func() {
			var listenAddr, secureListenAddr string

			BeforeEach(func() {
				skipDevContainer()
				var err error
				srv, err = NewServer(Opts{
					Handler:           handler,
					BindAddress:       "[::1]:0",
					SecureBindAddress: "[::1]:0",
					TLS: &options.TLS{
						Key:  &ipv6KeyDataSource,
						Cert: &ipv6CertDataSource,
					},
				})
				Expect(err).ToNot(HaveOccurred())

				s, ok := srv.(*server)
				Expect(ok).To(BeTrue())

				listenAddr = fmt.Sprintf("http://%s/", s.listener.Addr().String())
				secureListenAddr = fmt.Sprintf("https://%s/", s.tlsListener.Addr().String())
			})

			It("Starts the server and serves the handler on http", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := httpGet(ctx, listenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := io.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Starts the server and serves the handler on https", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := httpGet(ctx, secureListenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := io.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Stops both servers when the context is cancelled", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				_, err := httpGet(ctx, listenAddr)
				Expect(err).ToNot(HaveOccurred())
				_, err = httpGet(ctx, secureListenAddr)
				Expect(err).ToNot(HaveOccurred())

				cancel()

				Eventually(func() error {
					_, err := httpGet(ctx, listenAddr)
					return err
				}).Should(HaveOccurred())
				Eventually(func() error {
					_, err := httpGet(ctx, secureListenAddr)
					return err
				}).Should(HaveOccurred())
			})
		})
	})

	Context("getNetworkScheme", func() {
		DescribeTable("should return the scheme", func(in, expected string) {
			Expect(getNetworkScheme(in)).To(Equal(expected))
		},
			Entry("ipv4 address with no scheme", "127.0.0.1:0", "tcp"),
			Entry("ipv4 address with a tcp scheme", "tcp://127.0.0.1:0", "tcp"),
			Entry("ipv4 address with a http scheme", "http://192.168.0.1:1", "tcp"),
			Entry("ipv4 address with a unix scheme", "unix://172.168.16.2:2", "unix"),
			Entry("ipv4 address with a random scheme", "random://10.10.10.10:10", "random"),
			Entry("ipv6 address with no scheme", "[::1]:0", "tcp"),
			Entry("ipv6 address with a tcp scheme", "tcp://[::1]:0", "tcp"),
			Entry("ipv6 address with a http scheme", "http://[::ffff:c0a8:1]:1", "tcp"),
			Entry("ipv6 address with a unix scheme", "unix://[::ffff:aca8:1002]:2", "unix"),
			Entry("ipv6 address with a random scheme", "random://[::ffff:a0a:a0a]:10", "random"),
		)
	})

	Context("getListenAddress", func() {
		DescribeTable("should remove the scheme", func(in, expected string) {
			Expect(getListenAddress(in)).To(Equal(expected))
		},
			Entry("ipv4 address with no scheme", "127.0.0.1:0", "127.0.0.1:0"),
			Entry("ipv4 address with a tcp scheme", "tcp://127.0.0.1:0", "127.0.0.1:0"),
			Entry("ipv4 address with a http scheme", "http://192.168.0.1:1", "192.168.0.1:1"),
			Entry("ipv4 address with a unix scheme", "unix://172.168.16.2:2", "172.168.16.2:2"),
			Entry("ipv4 address with a random scheme", "random://10.10.10.10:10", "10.10.10.10:10"),
			Entry("ipv6 address with no scheme", "[::1]:0", "[::1]:0"),
			Entry("ipv6 address with a tcp scheme", "tcp://[::1]:0", "[::1]:0"),
			Entry("ipv6 address with a http scheme", "http://[::ffff:c0a8:1]:1", "[::ffff:c0a8:1]:1"),
			Entry("ipv6 address with a unix scheme", "unix://[::ffff:aca8:1002]:2", "[::ffff:aca8:1002]:2"),
			Entry("ipv6 address with a random scheme", "random://[::ffff:a0a:a0a]:10", "[::ffff:a0a:a0a]:10"),
		)
	})
})

func skipDevContainer() {
	if os.Getenv("DEVCONTAINER") != "" {
		Skip("Skipping testing in DevContainer environment")
	}
}
