package upstream

import (
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("TrimRequestURIPath", func() {
	type trimPathTableInput struct {
		input, output requestFactory
		prefix        string
	}

	DescribeTable("ServeHTTP",
		func(in *trimPathTableInput) {
			rw := httptest.NewRecorder()
			input := in.input()
			verify := func(w http.ResponseWriter, r *http.Request) {
				output := in.output()

				Expect(r.URL.Path).To(Equal(output.URL.Path))
				Expect(r.URL.RawPath).To(Equal(output.URL.RawPath))
				Expect(r.RequestURI).To(Equal(output.RequestURI))
			}
			subject := TrimRequestURIPath(in.prefix, http.HandlerFunc(verify))

			subject.ServeHTTP(rw, input)
		},
		Entry("with / prefix against a root request", &trimPathTableInput{
			input:  requestFactoryGet("http://trim-path.test/"),
			output: requestFactoryGet("http://trim-path.test/"),
			prefix: "/",
		}),
		Entry("with / prefix against a subdir request", &trimPathTableInput{
			input:  requestFactoryGet("http://trim-path.test/path"),
			output: requestFactoryGet("http://trim-path.test/path"),
			prefix: "/",
		}),
		Entry("with /path prefix against a root request", &trimPathTableInput{
			input:  requestFactoryGet("http://trim-path.test/"),
			output: requestFactoryGet("http://trim-path.test/"),
			prefix: "/path",
		}),
		Entry("with /path prefix against a subdir request", &trimPathTableInput{
			input:  requestFactoryGet("http://trim-path.test/path"),
			output: requestFactoryGet("http://trim-path.test/"),
			prefix: "/path",
		}),
		Entry("with /path prefix against a sub-subdir request", &trimPathTableInput{
			input:  requestFactoryGet("http://trim-path.test/path/else"),
			output: requestFactoryGet("http://trim-path.test/else"),
			prefix: "/path",
		}),
		Entry("with /path prefix against a sub-subdir request (repetition)", &trimPathTableInput{
			input:  requestFactoryGet("http://trim-path.test/path/path"),
			output: requestFactoryGet("http://trim-path.test/path"),
			prefix: "/path",
		}),
		Entry("with /path prefix against a sub-subdir request (suffix match)", &trimPathTableInput{
			input:  requestFactoryGet("http://trim-path.test/else/path"),
			output: requestFactoryGet("http://trim-path.test/else/path"),
			prefix: "/path",
		}),
	)
})
