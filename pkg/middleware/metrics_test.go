package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var _ = Describe("Instrumentation suite", func() {
	type requestTableInput struct {
		registry        *prometheus.Registry
		requestString   string
		expectedHandler http.Handler
		expectedMetrics []string
		expectedStatus  int
		// Prometheus output is large so is stored in testdata
		expectedResultsFile string
	}

	DescribeTable("when serving a request",
		func(in *requestTableInput) {
			req := httptest.NewRequest("", in.requestString, nil)

			rw := httptest.NewRecorder()

			handler := NewRequestMetrics(in.registry)(in.expectedHandler)
			handler.ServeHTTP(rw, req)

			Expect(rw.Code).To(Equal(in.expectedStatus))

			expectedPrometheusText, err := os.Open(in.expectedResultsFile)
			Expect(err).NotTo(HaveOccurred())

			err = testutil.GatherAndCompare(in.registry, expectedPrometheusText, in.expectedMetrics...)
			Expect(err).NotTo(HaveOccurred())
		},
		Entry("successfully", func() *requestTableInput {
			in := &requestTableInput{
				registry:      prometheus.NewRegistry(),
				requestString: "http://example.com/metrics",
				expectedMetrics: []string{
					"oauth2_proxy_requests_total",
				},
				expectedStatus:      200,
				expectedResultsFile: "testdata/metrics/successfulrequest.txt",
			}
			in.expectedHandler = NewMetricsHandler(in.registry, in.registry)

			return in
		}()),
		Entry("with not found", &requestTableInput{
			registry:            prometheus.NewRegistry(),
			requestString:       "http://example.com/",
			expectedHandler:     http.NotFoundHandler(),
			expectedMetrics:     []string{"oauth2_proxy_requests_total"},
			expectedStatus:      404,
			expectedResultsFile: "testdata/metrics/notfoundrequest.txt",
		}),
	)
})
