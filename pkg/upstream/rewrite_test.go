package upstream

import (
	"net/http"
	"net/http/httptest"
	"regexp"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/app/pagewriter"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Rewrite", func() {
	type rewritePathTableInput struct {
		rewriteRegex       *regexp.Regexp
		rewriteTarget      string
		requestTarget      string
		expectedRequestURI string
		expectedURLPath    string
	}

	DescribeTable("should rewrite the request path",
		func(in rewritePathTableInput) {
			req := httptest.NewRequest("", in.requestTarget, nil)
			rw := httptest.NewRecorder()

			var gotRequestURI string
			var gotRequestURLPath string
			handler := newRewritePath(in.rewriteRegex, in.rewriteTarget, &pagewriter.WriterFuncs{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotRequestURI = r.RequestURI
				gotRequestURLPath = r.URL.Path
			}))
			handler.ServeHTTP(rw, req)

			Expect(gotRequestURI).To(Equal(in.expectedRequestURI))
			Expect(gotRequestURLPath).To(Equal(in.expectedURLPath))
		},
		Entry("when the path matches the regexp", rewritePathTableInput{
			rewriteRegex:       regexp.MustCompile("^/http/(.*)"),
			rewriteTarget:      "/$1",
			requestTarget:      "http://example.com/http/foo/bar",
			expectedRequestURI: "http://example.com/foo/bar",
			expectedURLPath:    "/foo/bar",
		}),
		Entry("when the path does not match the regexp", rewritePathTableInput{
			rewriteRegex:       regexp.MustCompile("^/http/(.*)"),
			rewriteTarget:      "/$1",
			requestTarget:      "https://example.com/https/foo/bar",
			expectedRequestURI: "https://example.com/https/foo/bar",
			expectedURLPath:    "/https/foo/bar",
		}),
		Entry("when the regexp is not anchored", rewritePathTableInput{
			rewriteRegex:       regexp.MustCompile("/http/(.*)"),
			rewriteTarget:      "/$1",
			requestTarget:      "http://example.com/bar/http/foo/bar",
			expectedRequestURI: "http://example.com/bar/foo/bar",
			expectedURLPath:    "/bar/foo/bar",
		}),
		Entry("when the regexp is rewriting to a query", rewritePathTableInput{
			rewriteRegex:       regexp.MustCompile(`/articles/([a-z0-9\-]*)`),
			rewriteTarget:      "/article?id=$1",
			requestTarget:      "http://example.com/articles/blog-2021-01-01",
			expectedRequestURI: "http://example.com/article?id=blog-2021-01-01",
			expectedURLPath:    "/article",
		}),
		Entry("when the path contains percent-encoded characters, the encoding is preserved", rewritePathTableInput{
			rewriteRegex:       regexp.MustCompile("^/app/prefix/(.*)$"),
			rewriteTarget:      "/$1",
			requestTarget:      "http://example.com/app/prefix/v1/id/data%3Aabc%2Fdef",
			expectedRequestURI: "http://example.com/v1/id/data%3Aabc%2Fdef",
			expectedURLPath:    "/v1/id/data:abc/def",
		}),
		Entry("when the encoded path is rewritten and an original query is preserved", rewritePathTableInput{
			rewriteRegex:       regexp.MustCompile("^/app/prefix/(.*)$"),
			rewriteTarget:      "/$1",
			requestTarget:      "http://example.com/app/prefix/data%2Fone?foo=bar",
			expectedRequestURI: "http://example.com/data%2Fone?foo=bar",
			expectedURLPath:    "/data/one",
		}),
		Entry("when the encoded path is matched by a non-anchored regexp", rewritePathTableInput{
			rewriteRegex:       regexp.MustCompile("/prefix/(.*)"),
			rewriteTarget:      "/$1",
			requestTarget:      "http://example.com/app/prefix/data%2Fone",
			expectedRequestURI: "http://example.com/app/data%2Fone",
			expectedURLPath:    "/app/data/one",
		}),
	)
})
