package validation

import (
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Upstreams", func() {
	type validateUpstreamTableInput struct {
		upstreams  options.UpstreamConfig
		errStrings []string
	}

	flushInterval := options.Duration(5 * time.Second)
	staticCode200 := 200
	truth := true

	validHTTPUpstream := options.Upstream{
		ID:   "validHTTPUpstream",
		Path: "/validHTTPUpstream",
		URI:  "http://localhost:8080",
	}
	validStaticUpstream := options.Upstream{
		ID:     "validStaticUpstream",
		Path:   "/validStaticUpstream",
		Static: true,
	}
	validFileUpstream := options.Upstream{
		ID:   "validFileUpstream",
		Path: "/validFileUpstream",
		URI:  "file://var/lib/foo",
	}

	emptyIDMsg := "upstream has empty id: ids are required for all upstreams"
	emptyPathMsg := "upstream \"foo\" has empty path: paths are required for all upstreams"
	emptyURIMsg := "upstream \"foo\" has empty uri: uris are required for all non-static upstreams"
	invalidURIMsg := "upstream \"foo\" has invalid uri: parse \":\": missing protocol scheme"
	invalidURISchemeMsg := "upstream \"foo\" has invalid scheme: \"ftp\""
	staticWithURIMsg := "upstream \"foo\" has uri, but is a static upstream, this will have no effect."
	staticWithInsecureMsg := "upstream \"foo\" has insecureSkipTLSVerify, but is a static upstream, this will have no effect."
	staticWithFlushIntervalMsg := "upstream \"foo\" has flushInterval, but is a static upstream, this will have no effect."
	staticWithPassHostHeaderMsg := "upstream \"foo\" has passHostHeader, but is a static upstream, this will have no effect."
	staticWithProxyWebSocketsMsg := "upstream \"foo\" has proxyWebSockets, but is a static upstream, this will have no effect."
	multipleIDsMsg := "multiple upstreams found with id \"foo\": upstream ids must be unique"
	multiplePathsMsg := "multiple upstreams found with path \"/foo\": upstream paths must be unique"
	staticCodeMsg := "upstream \"foo\" has staticCode (200), but is not a static upstream, set 'static' for a static response"

	DescribeTable("validateUpstreams",
		func(o *validateUpstreamTableInput) {
			Expect(validateUpstreams(o.upstreams)).To(ConsistOf(o.errStrings))
		},
		Entry("with no upstreams", &validateUpstreamTableInput{
			upstreams:  options.UpstreamConfig{},
			errStrings: []string{},
		}),
		Entry("with valid upstreams", &validateUpstreamTableInput{
			upstreams: options.UpstreamConfig{
				Upstreams: []options.Upstream{
					validHTTPUpstream,
					validStaticUpstream,
					validFileUpstream,
				},
			},
			errStrings: []string{},
		}),
		Entry("with an empty ID", &validateUpstreamTableInput{
			upstreams: options.UpstreamConfig{
				Upstreams: []options.Upstream{
					{
						ID:   "",
						Path: "/foo",
						URI:  "http://localhost:8080",
					},
				},
			},
			errStrings: []string{emptyIDMsg},
		}),
		Entry("with an empty Path", &validateUpstreamTableInput{
			upstreams: options.UpstreamConfig{
				Upstreams: []options.Upstream{
					{
						ID:   "foo",
						Path: "",
						URI:  "http://localhost:8080",
					},
				},
			},
			errStrings: []string{emptyPathMsg},
		}),
		Entry("with an empty Path", &validateUpstreamTableInput{
			upstreams: options.UpstreamConfig{
				Upstreams: []options.Upstream{
					{
						ID:   "foo",
						Path: "",
						URI:  "http://localhost:8080",
					},
				},
			},
			errStrings: []string{emptyPathMsg},
		}),
		Entry("with an empty URI", &validateUpstreamTableInput{
			upstreams: options.UpstreamConfig{
				Upstreams: []options.Upstream{
					{
						ID:   "foo",
						Path: "/foo",
						URI:  "",
					},
				},
			},
			errStrings: []string{emptyURIMsg},
		}),
		Entry("with an invalid URI", &validateUpstreamTableInput{
			upstreams: options.UpstreamConfig{
				Upstreams: []options.Upstream{
					{
						ID:   "foo",
						Path: "/foo",
						URI:  ":",
					},
				},
			},
			errStrings: []string{invalidURIMsg},
		}),
		Entry("with an invalid URI scheme", &validateUpstreamTableInput{
			upstreams: options.UpstreamConfig{
				Upstreams: []options.Upstream{
					{
						ID:   "foo",
						Path: "/foo",
						URI:  "ftp://foo",
					},
				},
			},
			errStrings: []string{invalidURISchemeMsg},
		}),
		Entry("with a static upstream and invalid optons", &validateUpstreamTableInput{
			upstreams: options.UpstreamConfig{
				Upstreams: []options.Upstream{
					{
						ID:                    "foo",
						Path:                  "/foo",
						URI:                   "ftp://foo",
						Static:                true,
						FlushInterval:         &flushInterval,
						PassHostHeader:        &truth,
						ProxyWebSockets:       &truth,
						InsecureSkipTLSVerify: true,
					},
				},
			},
			errStrings: []string{
				staticWithURIMsg,
				staticWithInsecureMsg,
				staticWithFlushIntervalMsg,
				staticWithPassHostHeaderMsg,
				staticWithProxyWebSocketsMsg,
			},
		}),
		Entry("with duplicate IDs", &validateUpstreamTableInput{
			upstreams: options.UpstreamConfig{
				Upstreams: []options.Upstream{
					{
						ID:   "foo",
						Path: "/foo1",
						URI:  "http://foo",
					},
					{
						ID:   "foo",
						Path: "/foo2",
						URI:  "http://foo",
					},
				},
			},
			errStrings: []string{multipleIDsMsg},
		}),
		Entry("with duplicate Paths", &validateUpstreamTableInput{
			upstreams: options.UpstreamConfig{
				Upstreams: []options.Upstream{
					{
						ID:   "foo1",
						Path: "/foo",
						URI:  "http://foo",
					},
					{
						ID:   "foo2",
						Path: "/foo",
						URI:  "http://foo",
					},
				},
			},
			errStrings: []string{multiplePathsMsg},
		}),
		Entry("when a static code is supplied without static", &validateUpstreamTableInput{
			upstreams: options.UpstreamConfig{
				Upstreams: []options.Upstream{
					{
						ID:         "foo",
						Path:       "/foo",
						StaticCode: &staticCode200,
					},
				},
			},
			errStrings: []string{emptyURIMsg, staticCodeMsg},
		}),
	)
})
