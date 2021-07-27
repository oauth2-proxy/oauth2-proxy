package middleware

import (
	"net/http"

	"github.com/justinas/alice"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// DefaultMetricsHandler is the default http.Handler for serving metrics from
// the default prometheus.Registry
var DefaultMetricsHandler = NewMetricsHandlerWithDefaultRegistry()

// NewMetricsHandlerWithDefaultRegistry creates a new http.Handler for serving
// metrics from the default prometheus.Registry.
func NewMetricsHandlerWithDefaultRegistry() http.Handler {
	return NewMetricsHandler(prometheus.DefaultRegisterer, prometheus.DefaultGatherer)
}

// NewMetricsHandler creates a new http.Handler for serving metrics from the
// provided prometheus.Registerer and prometheus.Gatherer
func NewMetricsHandler(registerer prometheus.Registerer, gatherer prometheus.Gatherer) http.Handler {
	return promhttp.InstrumentMetricHandler(
		registerer, promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{}),
	)
}

// NewRequestMetricsWithDefaultRegistry returns a middleware that will record
// metrics for HTTP requests to the default prometheus.Registry
func NewRequestMetricsWithDefaultRegistry() alice.Constructor {
	return NewRequestMetrics(prometheus.DefaultRegisterer)
}

// NewRequestMetrics returns a middleware that will record metrics for HTTP
// requests to the provided prometheus.Registerer
func NewRequestMetrics(registerer prometheus.Registerer) alice.Constructor {
	return func(next http.Handler) http.Handler {
		// Counter for all requests
		// This is bucketed based on the response code we set
		counterHandler := func(next http.Handler) http.Handler {
			return promhttp.InstrumentHandlerCounter(registerRequestsCounter(registerer), next)
		}

		// Gauge to all requests currently being handled
		inFlightHandler := func(next http.Handler) http.Handler {
			return promhttp.InstrumentHandlerInFlight(registerInflightRequestsGauge(registerer), next)
		}

		// The latency of all requests bucketed by HTTP method
		durationHandler := func(next http.Handler) http.Handler {
			return promhttp.InstrumentHandlerDuration(registerRequestsLatencyHistogram(registerer), next)
		}

		return alice.New(counterHandler, inFlightHandler, durationHandler).Then(next)
	}
}

// registerRequestsCounter registers the 'oauth2_proxy_requests_total' metric
// This keeps a tally of all received requests bucket by their HTTP response
// status code
func registerRequestsCounter(registerer prometheus.Registerer) *prometheus.CounterVec {
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oauth2_proxy_requests_total",
			Help: "Total number of requests by HTTP status code.",
		},
		[]string{"code"},
	)

	if err := registerer.Register(counter); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			counter = are.ExistingCollector.(*prometheus.CounterVec)
		} else {
			panic(err)
		}
	}

	return counter
}

// registerInflightRequestsGauge registers 'oauth2_proxy_requests_in_flight'
// This only keeps the count of currently in progress HTTP requests
func registerInflightRequestsGauge(registerer prometheus.Registerer) prometheus.Gauge {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "oauth2_proxy_requests_in_flight",
		Help: "Current number of requests being served.",
	})

	if err := registerer.Register(gauge); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			gauge = are.ExistingCollector.(prometheus.Gauge)
		} else {
			panic(err)
		}
	}

	return gauge
}

// registerRequestsLatencyHistogram registers 'oauth2_proxy_response_duration_seconds'
// This keeps tally of the requests bucketed by the time taken to process the request
func registerRequestsLatencyHistogram(registerer prometheus.Registerer) *prometheus.HistogramVec {
	histogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "oauth2_proxy_response_duration_seconds",
			Help:    "A histogram of request latencies.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method"},
	)

	if err := registerer.Register(histogram); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			histogram = are.ExistingCollector.(*prometheus.HistogramVec)
		} else {
			panic(err)
		}
	}

	return histogram
}
