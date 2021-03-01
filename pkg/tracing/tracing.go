package tracing

import (
	"context"
	"net/http"
)

type key int

var tracingHeadersKey key

func NewTracingContext(req *http.Request) context.Context {
	headers := http.Header{}
	addHeader := func(header string) {
		if val := req.Header.Get(header); val != "" {
			headers.Set(header, val)
		}
	}

	// https://istio.io/latest/faq/distributed-tracing/#how-to-support-tracing
	addHeader("x-request-id")
	addHeader("x-b3-traceid")
	addHeader("x-b3-spanid")
	addHeader("x-b3-parentspanid")
	addHeader("x-b3-sampled")
	addHeader("x-b3-flags")
	addHeader("b3")
	addHeader("x-ot-span-context")

	return context.WithValue(req.Context(), tracingHeadersKey, &headers)
}

func TracingFromContext(ctx context.Context) (*http.Header, bool) {
	u, ok := ctx.Value(tracingHeadersKey).(*http.Header)
	return u, ok
}
