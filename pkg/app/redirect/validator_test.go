package redirect

import (
	"bufio"
	"net/url"
	"os"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Validator suite", func() {
	var testAllowedDomains []string

	BeforeEach(func() {
		testAllowedDomains = []string{
			"foo.bar",
			".bar.foo",
			"port.bar:8080",
			".sub.port.bar:8080",
			"anyport.bar:*",
			".sub.anyport.bar:*",
			"www.whitelisteddomain.tld",
			"*.wildcard.sub.port.bar:8080",
			"*.wildcard.sub.anyport.bar:*",
			"*.wildcard.bar",
			"*.wildcard.proxy.foo.bar",
		}
	})

	Context("OpenRedirect List", func() {
		file, err := os.Open("../../../testdata/openredirects.txt")
		Expect(err).ToNot(HaveOccurred())
		defer func() {
			Expect(file.Close()).To(Succeed())
		}()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			rd := scanner.Text()
			It(rd, func() {
				rdUnescaped, err := url.QueryUnescape(rd)
				Expect(err).ToNot(HaveOccurred())

				validator := NewValidator(testAllowedDomains)
				Expect(validator.IsValidRedirect(rdUnescaped)).To(BeFalse(), "Expected redirect not to be valid")
			})
		}

		Expect(scanner.Err()).ToNot(HaveOccurred())
	})

	Context("Validator", func() {
		DescribeTable("IsValidRedirect",
			func(testRedirect string, expected bool) {
				validator := NewValidator(testAllowedDomains)
				Expect(validator.IsValidRedirect(testRedirect)).To(Equal(expected))
			},
			Entry("No Redirect", "", false),
			Entry("Single Slash", "/redirect", true),
			Entry("Double Slash", "//redirect", false),
			Entry("Valid HTTP", "http://foo.bar/redirect", true),
			Entry("Valid HTTPS", "https://foo.bar/redirect", true),
			Entry("Invalid HTTP subdomain", "http://baz.foo.bar/redirect", false),
			Entry("Invalid HTTPS subdomain", "https://baz.foo.bar/redirect", false),
			Entry("Valid HTTP subdomain", "http://baz.bar.foo/redirect", true),
			Entry("Valid HTTPS subdomain", "https://baz.bar.foo/redirect", true),
			Entry("Valid HTTP Domain", "http://bar.foo/redirect", true), // Is this correct, do we want to match the root domain?
			Entry("Invalid HTTP Similar Domain", "http://foo.bar.evil.corp/redirect", false),
			Entry("Invalid HTTPS Similar Domain", "https://foo.bar.evil.corp/redirect", false),
			Entry("Invalid HTTP RD Parameter", "http://evil.corp/redirect?rd=foo.bar", false),
			Entry("Invalid HTTPS RD Parameter", "https://evil.corp/redirect?rd=foo.bar", false),
			Entry("Invalid Port and Domain", "https://evil.corp:3838/redirect", false),
			Entry("Invalid Port on Allowed Domain", "http://foo.bar:3838/redirect", false),
			Entry("Invalid Port on Allowed Subdomain", "http://baz.bar.foo:3838/redirect", false),
			Entry("Valid Specified Port and Domain", "http://port.bar:8080/redirect", true),
			Entry("Invalid Specified Port and Domain", "http://port.bar:3838/redirect", false),
			Entry("Valid Specified Port and Subdomain", "http://foo.sub.port.bar:8080/redirect", true),
			Entry("Invalid Specified Port andSubdomain", "http://foo.subport.bar:3838/redirect", false),
			Entry("Valid Any Port, Specified Domain", "http://anyport.bar:8080/redirect", true),
			Entry("Valid Different Any Port, Specified Domain", "http://anyport.bar:8081/redirect", true),
			Entry("Valid Any Port, Specified Subdomain", "http://a.sub.anyport.bar:8080/redirect", true),
			Entry("Valid Different Any Port, Specified Subdomain", "http://a.sub.anyport.bar:8081/redirect", true),
			Entry("Escape Double Slash", "/\\evil.com", false),
			Entry("Space Single Slash", "/ /evil.com", false),
			Entry("Space Double Slash", "/ \\evil.com", false),
			Entry("Tab Single Slash", "/\t/evil.com", false),
			Entry("Tab Double Slash", "/\t\\evil.com", false),
			Entry("Vertical Tab Single Slash", "/\v/evil.com", false),
			Entry("Vertiacl Tab Double Slash", "/\v\\evil.com", false),
			Entry("New Line Single Slash", "/\n/evil.com", false),
			Entry("New Line Double Slash", "/\n\\evil.com", false),
			Entry("Carriage Return Single Slash", "/\r/evil.com", false),
			Entry("Carriage Return Double Slash", "/\r\\evil.com", false),
			Entry("Double Tab", "/\t/\t\\evil.com", false),
			Entry("Triple Tab 1", "/\t\t/\t/evil.com", false),
			Entry("Triple Tab 2", "/\t\t\\\t/evil.com", false),
			Entry("Quad Tab 1", "/\t\t/\t\t\\evil.com", false),
			Entry("Quad Tab 2", "/\t\t\\\t\t/evil.com", false),
			Entry("Relative Path", "/./\\evil.com", false),
			Entry("Relative Subpath", "/./../../\\evil.com", false),
			Entry("Valid HTTP Wildcard Subdomain", "http://foo.wildcard.bar/redirect", true),
			Entry("Valid HTTPS Wildcard Subdomain", "https://foo.wildcard.bar/redirect", true),
			Entry("Valid HTTP Wildcard Subdomain Root", "http://wildcard.bar/redirect", true),
			Entry("Valid HTTPS Wildcard Subdomain Root", "https://wildcard.bar/redirect", true),
			Entry("Valid HTTP Wildcard Subdomain anyport", "http://foo.wildcard.sub.anyport.bar:4242/redirect", true),
			Entry("Valid HTTPS Wildcard Subdomain anyport", "https://foo.wildcard.sub.anyport.bar:4242/redirect", true),
			Entry("Valid HTTP Wildcard Subdomain Anyport Root", "http://wildcard.sub.anyport.bar:4242/redirect", true),
			Entry("Valid HTTPS Wildcard Subdomain Anyport Root", "https://wildcard.sub.anyport.bar:4242/redirect", true),
			Entry("Valid HTTP Wildcard Subdomain Defined Port", "http://foo.wildcard.sub.port.bar:8080/redirect", true),
			Entry("Valid HTTPS Wildcard Subdomain Defined Port", "https://foo.wildcard.sub.port.bar:8080/redirect", true),
			Entry("Valid HTTP Wildcard Subdomain Defined Port Root", "http://wildcard.sub.port.bar:8080/redirect", true),
			Entry("Valid HTTPS Wildcard Subdomain Defined Port Root", "https://wildcard.sub.port.bar:8080/redirect", true),
			Entry("Missing Protocol Root Domain", "foo.bar/redirect", false),
			Entry("Missing Protocol Wildcard Subdomain", "proxy.wildcard.bar/redirect", false),
		)
	})

	Context("SplitHostPort", func() {
		type splitHostPortTableInput struct {
			hostport     string
			expectedHost string
			expectedPort string
		}

		DescribeTable("Should split the host and port",
			func(in splitHostPortTableInput) {
				host, port := util.SplitHostPort(in.hostport)
				Expect(host).To(Equal(in.expectedHost))
				Expect(port).To(Equal(in.expectedPort))
			},
			Entry("when no port is specified", splitHostPortTableInput{
				hostport:     "foo.bar",
				expectedHost: "foo.bar",
				expectedPort: "",
			}),
			Entry("with a valid port specified", splitHostPortTableInput{
				hostport:     "foo.bar:8080",
				expectedHost: "foo.bar",
				expectedPort: "8080",
			}),
			Entry("with an invalid port specified", splitHostPortTableInput{
				hostport:     "foo.bar:808a",
				expectedHost: "foo.bar:808a",
				expectedPort: "",
			}),
			Entry("with a wildcard port specified", splitHostPortTableInput{
				hostport:     "foo.bar:*",
				expectedHost: "foo.bar",
				expectedPort: "*",
			}),
			Entry("when the host is specified with brackets", splitHostPortTableInput{
				hostport:     "[foo.bar]",
				expectedHost: "foo.bar",
				expectedPort: "",
			}),
		)
	})
})
