package healthcheck

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Healthcheck", func() {
	Describe("normalizeAddress", func() {
		type normalizeInput struct {
			input    string
			expected string
		}

		DescribeTable("should strip scheme prefixes and whitespace",
			func(in normalizeInput) {
				Expect(normalizeAddress(in.input)).To(Equal(in.expected))
			},
			Entry("plain address", normalizeInput{
				input: "127.0.0.1:4180", expected: "127.0.0.1:4180",
			}),
			Entry("with http scheme", normalizeInput{
				input: "http://127.0.0.1:4180", expected: "127.0.0.1:4180",
			}),
			Entry("with https scheme", normalizeInput{
				input: "https://127.0.0.1:443", expected: "127.0.0.1:443",
			}),
			Entry("with leading whitespace", normalizeInput{
				input: "  127.0.0.1:4180", expected: "127.0.0.1:4180",
			}),
			Entry("empty string", normalizeInput{
				input: "", expected: "",
			}),
			Entry("disabled address", normalizeInput{
				input: "-", expected: "-",
			}),
		)
	})

	Describe("replaceUnspecified", func() {
		type replaceInput struct {
			input    string
			expected string
		}

		DescribeTable("should replace unspecified addresses with loopback",
			func(in replaceInput) {
				Expect(replaceUnspecified(in.input)).To(Equal(in.expected))
			},
			Entry("empty string", replaceInput{
				input: "", expected: "127.0.0.1",
			}),
			Entry("IPv4 unspecified", replaceInput{
				input: "0.0.0.0", expected: "127.0.0.1",
			}),
			Entry("IPv6 unspecified (::)", replaceInput{
				input: "::", expected: "::1",
			}),
			Entry("IPv6 unspecified with brackets", replaceInput{
				input: "[::]", expected: "::1",
			}),
			Entry("IPv4 localhost", replaceInput{
				input: "127.0.0.1", expected: "127.0.0.1",
			}),
			Entry("specific IPv4 address", replaceInput{
				input: "10.0.0.1", expected: "10.0.0.1",
			}),
		)
	})

	Describe("Run", func() {
		var (
			server   *httptest.Server
			listener net.Listener
		)

		AfterEach(func() {
			if server != nil {
				server.Close()
			}
		})

		It("should succeed when ping endpoint returns 200", func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/ping" {
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, "OK")
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))

			// Extract host:port from the test server URL
			addr := server.Listener.Addr().String()

			opts := CheckOptions{
				HTTPAddress: addr,
				PingPath:    "/ping",
				Timeout:     2 * time.Second,
			}

			Expect(Run(opts)).To(Succeed())
		})

		It("should fail when ping endpoint returns non-200", func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprint(w, "not ready")
			}))

			addr := server.Listener.Addr().String()

			opts := CheckOptions{
				HTTPAddress: addr,
				PingPath:    "/ping",
				Timeout:     2 * time.Second,
			}

			err := Run(opts)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("status 503"))
		})

		It("should fail when server is not reachable", func() {
			// Use a random port that is unlikely to have a server
			listener, _ = net.Listen("tcp", "127.0.0.1:0")
			addr := listener.Addr().String()
			listener.Close() // Close immediately so the port is free but nothing is listening

			opts := CheckOptions{
				HTTPAddress: addr,
				PingPath:    "/ping",
				Timeout:     1 * time.Second,
			}

			err := Run(opts)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("health check failed"))
		})

		It("should fail when no address is configured", func() {
			opts := CheckOptions{
				HTTPAddress:  "",
				HTTPSAddress: "",
				PingPath:     "/ping",
				Timeout:      1 * time.Second,
			}

			err := Run(opts)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no bind address configured"))
		})

		It("should fail when address is disabled with -", func() {
			opts := CheckOptions{
				HTTPAddress:  "-",
				HTTPSAddress: "-",
				PingPath:     "/ping",
				Timeout:      1 * time.Second,
			}

			err := Run(opts)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no bind address configured"))
		})

		It("should use default ping path when not specified", func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/ping" {
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, "OK")
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))

			addr := server.Listener.Addr().String()

			opts := CheckOptions{
				HTTPAddress: addr,
				PingPath:    "", // should default to /ping
				Timeout:     2 * time.Second,
			}

			Expect(Run(opts)).To(Succeed())
		})

		It("should use a custom ping path", func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/healthz" {
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, "OK")
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))

			addr := server.Listener.Addr().String()

			opts := CheckOptions{
				HTTPAddress: addr,
				PingPath:    "/healthz",
				Timeout:     2 * time.Second,
			}

			Expect(Run(opts)).To(Succeed())
		})

		It("should handle address with http:// scheme prefix", func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "OK")
			}))

			addr := server.Listener.Addr().String()

			opts := CheckOptions{
				HTTPAddress: "http://" + addr,
				PingPath:    "/ping",
				Timeout:     2 * time.Second,
			}

			Expect(Run(opts)).To(Succeed())
		})

		It("should fall back to HTTPS when HTTP address is empty", func() {
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/ping" {
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, "OK")
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))

			addr := server.Listener.Addr().String()

			opts := CheckOptions{
				HTTPAddress:        "",
				HTTPSAddress:       addr,
				PingPath:           "/ping",
				Timeout:            2 * time.Second,
				InsecureSkipVerify: true,
			}

			Expect(Run(opts)).To(Succeed())
		})

		It("should respect timeout", func() {
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Simulate a slow server
				time.Sleep(3 * time.Second)
				w.WriteHeader(http.StatusOK)
			}))

			addr := server.Listener.Addr().String()

			opts := CheckOptions{
				HTTPAddress: addr,
				PingPath:    "/ping",
				Timeout:     500 * time.Millisecond,
			}

			err := Run(opts)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("health check failed"))
		})
	})

	Describe("DefaultCheckOptions", func() {
		It("should return sensible defaults", func() {
			opts := DefaultCheckOptions()
			Expect(opts.HTTPAddress).To(Equal(DefaultHTTPAddress))
			Expect(opts.PingPath).To(Equal(DefaultPingPath))
			Expect(opts.Timeout).To(Equal(DefaultTimeout))
			Expect(opts.HTTPSAddress).To(BeEmpty())
			Expect(opts.InsecureSkipVerify).To(BeFalse())
		})
	})
})
