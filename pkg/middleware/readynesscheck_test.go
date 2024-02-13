package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ReadynessCheck suite", func() {
	type requestTableInput struct {
		readyPath        string
		healthVerifiable Verifiable
		requestString    string
		expectedStatus   int
		expectedBody     string
	}

	DescribeTable("when serving a request",
		func(in *requestTableInput) {
			req := httptest.NewRequest("", in.requestString, nil)

			rw := httptest.NewRecorder()

			handler := NewReadynessCheck(in.readyPath, in.healthVerifiable)(http.NotFoundHandler())
			handler.ServeHTTP(rw, req)

			Expect(rw.Code).To(Equal(in.expectedStatus))
			Expect(rw.Body.String()).To(Equal(in.expectedBody))
		},
		Entry("when requesting the readyness check path", &requestTableInput{
			readyPath:        "/ready",
			healthVerifiable: &fakeVerifiable{nil},
			requestString:    "http://example.com/ready",
			expectedStatus:   200,
			expectedBody:     "OK",
		}),
		Entry("when requesting a different path", &requestTableInput{
			readyPath:        "/ready",
			healthVerifiable: &fakeVerifiable{nil},
			requestString:    "http://example.com/different",
			expectedStatus:   404,
			expectedBody:     "404 page not found\n",
		}),
		Entry("when a blank string is configured as a readyness check path and the request has no specific path", &requestTableInput{
			readyPath:        "",
			healthVerifiable: &fakeVerifiable{nil},
			requestString:    "http://example.com",
			expectedStatus:   404,
			expectedBody:     "404 page not found\n",
		}),
		Entry("with full health check and without an underlying error", &requestTableInput{
			readyPath:        "/ready",
			healthVerifiable: &fakeVerifiable{nil},
			requestString:    "http://example.com/ready",
			expectedStatus:   200,
			expectedBody:     "OK",
		}),
		Entry("with full health check and with an underlying error", &requestTableInput{
			readyPath:        "/ready",
			healthVerifiable: &fakeVerifiable{func(ctx context.Context) error { return errors.New("failed to check") }},
			requestString:    "http://example.com/ready",
			expectedStatus:   500,
			expectedBody:     "error: failed to check",
		}),
	)
})

type fakeVerifiable struct {
	mock func(context.Context) error
}

func (v *fakeVerifiable) VerifyConnection(ctx context.Context) error {
	if v.mock != nil {
		return v.mock(ctx)
	}
	return nil
}

var _ Verifiable = (*fakeVerifiable)(nil)
