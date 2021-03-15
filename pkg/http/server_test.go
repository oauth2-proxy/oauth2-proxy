package http

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
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
		}

		DescribeTable("When creating the new server from the options", func(in *newServerTableInput) {
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
			Entry("with a valid http bind address", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "127.0.0.1:0",
				},
				expectedErr:        nil,
				expectHTTPListener: true,
				expectTLSListener:  false,
			}),
			Entry("with a valid https bind address, with no TLS config", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
				},
				expectedErr:        errors.New("error setting up TLS listener: no TLS config provided"),
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("with a valid https bind address, and valid TLS config", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key:  &keyDataSource,
						Cert: &certDataSource,
					},
				},
				expectedErr:        nil,
				expectHTTPListener: false,
				expectTLSListener:  true,
			}),
			Entry("with a both a valid http and valid https bind address, and valid TLS config", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					BindAddress:       "127.0.0.1:0",
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key:  &keyDataSource,
						Cert: &certDataSource,
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
			Entry("with an invalid bind address scheme", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "invalid://127.0.0.1:0",
				},
				expectedErr:        errors.New("error setting up listener: listen (invalid, 127.0.0.1:0) failed: listen invalid: unknown network invalid"),
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("with an invalid secure bind address scheme", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "invalid://127.0.0.1:0",
					TLS: &options.TLS{
						Key:  &keyDataSource,
						Cert: &certDataSource,
					},
				},
				expectedErr:        nil,
				expectHTTPListener: false,
				expectTLSListener:  true,
			}),
			Entry("with an invalid bind address port", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "127.0.0.1:a",
				},
				expectedErr:        errors.New("error setting up listener: listen (tcp, 127.0.0.1:a) failed: listen tcp: lookup tcp/a: "),
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("with an invalid secure bind address port", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:a",
					TLS: &options.TLS{
						Key:  &keyDataSource,
						Cert: &certDataSource,
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: listen (127.0.0.1:a) failed: listen tcp: lookup tcp/a: "),
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("with an invalid TLS key", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key: &options.SecretSource{
							Value: []byte("invalid"),
						},
						Cert: &certDataSource,
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: could not load certificate: could not parse certificate data: tls: failed to find any PEM data in key input"),
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("with an invalid TLS cert", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key: &keyDataSource,
						Cert: &options.SecretSource{
							Value: []byte("invalid"),
						},
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: could not load certificate: could not parse certificate data: tls: failed to find any PEM data in certificate input"),
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("with no TLS key", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Cert: &certDataSource,
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: could not load certificate: could not load key data: no configuration provided"),
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("with no TLS cert", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key: &keyDataSource,
					},
				},
				expectedErr:        errors.New("error setting up TLS listener: could not load certificate: could not load cert data: no configuration provided"),
				expectHTTPListener: false,
				expectTLSListener:  false,
			}),
			Entry("when the bind address is prefixed with the http scheme", &newServerTableInput{
				opts: Opts{
					Handler:     handler,
					BindAddress: "http://127.0.0.1:0",
				},
				expectedErr:        nil,
				expectHTTPListener: true,
				expectTLSListener:  false,
			}),
			Entry("when the secure bind address is prefixed with the https scheme", &newServerTableInput{
				opts: Opts{
					Handler:           handler,
					SecureBindAddress: "https://127.0.0.1:0",
					TLS: &options.TLS{
						Key:  &keyDataSource,
						Cert: &certDataSource,
					},
				},
				expectedErr:        nil,
				expectHTTPListener: false,
				expectTLSListener:  true,
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
		})

		Context("with an http server", func() {
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

				resp, err := client.Get(listenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Stops the server when the context is cancelled", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				_, err := client.Get(listenAddr)
				Expect(err).ToNot(HaveOccurred())

				cancel()

				Eventually(func() error {
					_, err := client.Get(listenAddr)
					return err
				}).Should(HaveOccurred())
			})
		})

		Context("with an https server", func() {
			var secureListenAddr string

			BeforeEach(func() {
				var err error
				srv, err = NewServer(Opts{
					Handler:           handler,
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key:  &keyDataSource,
						Cert: &certDataSource,
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

				resp, err := client.Get(secureListenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Stops the server when the context is cancelled", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				_, err := client.Get(secureListenAddr)
				Expect(err).ToNot(HaveOccurred())

				cancel()

				Eventually(func() error {
					_, err := client.Get(secureListenAddr)
					return err
				}).Should(HaveOccurred())
			})

			It("Serves the certificate provided", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := client.Get(secureListenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				Expect(resp.TLS.VerifiedChains).Should(HaveLen(1))
				Expect(resp.TLS.VerifiedChains[0]).Should(HaveLen(1))
				Expect(resp.TLS.VerifiedChains[0][0].Raw).Should(Equal(certData))
			})
		})

		Context("with both an http and an https server", func() {
			var listenAddr, secureListenAddr string

			BeforeEach(func() {
				var err error
				srv, err = NewServer(Opts{
					Handler:           handler,
					BindAddress:       "127.0.0.1:0",
					SecureBindAddress: "127.0.0.1:0",
					TLS: &options.TLS{
						Key:  &keyDataSource,
						Cert: &certDataSource,
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

				resp, err := client.Get(listenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Starts the server and serves the handler on https", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				resp, err := client.Get(secureListenAddr)
				Expect(err).ToNot(HaveOccurred())
				Expect(resp.StatusCode).To(Equal(http.StatusOK))

				body, err := ioutil.ReadAll(resp.Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(hello))
			})

			It("Stops both servers when the context is cancelled", func() {
				go func() {
					defer GinkgoRecover()
					Expect(srv.Start(ctx)).To(Succeed())
				}()

				_, err := client.Get(listenAddr)
				Expect(err).ToNot(HaveOccurred())
				_, err = client.Get(secureListenAddr)
				Expect(err).ToNot(HaveOccurred())

				cancel()

				Eventually(func() error {
					_, err := client.Get(listenAddr)
					return err
				}).Should(HaveOccurred())
				Eventually(func() error {
					_, err := client.Get(secureListenAddr)
					return err
				}).Should(HaveOccurred())
			})
		})
	})

	Context("getNetworkScheme", func() {
		DescribeTable("should return the scheme", func(in, expected string) {
			Expect(getNetworkScheme(in)).To(Equal(expected))
		},
			Entry("with no scheme", "127.0.0.1:0", "tcp"),
			Entry("with a tcp scheme", "tcp://127.0.0.1:0", "tcp"),
			Entry("with a http scheme", "http://192.168.0.1:1", "tcp"),
			Entry("with a unix scheme", "unix://172.168.16.2:2", "unix"),
			Entry("with a random scheme", "random://10.10.10.10:10", "random"),
		)
	})

	Context("getListenAddress", func() {
		DescribeTable("should remove the scheme", func(in, expected string) {
			Expect(getListenAddress(in)).To(Equal(expected))
		},
			Entry("with no scheme", "127.0.0.1:0", "127.0.0.1:0"),
			Entry("with a tcp scheme", "tcp://127.0.0.1:0", "127.0.0.1:0"),
			Entry("with a http scheme", "http://192.168.0.1:1", "192.168.0.1:1"),
			Entry("with a unix scheme", "unix://172.168.16.2:2", "172.168.16.2:2"),
			Entry("with a random scheme", "random://10.10.10.10:10", "10.10.10.10:10"),
		)
	})
})
