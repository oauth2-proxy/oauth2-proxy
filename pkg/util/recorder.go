package util

import (
	"net/http"
)

// ResponseRecorder is an implementation of [http.ResponseWriter] that
// records its mutations for later inspection in tests.

const (
	ResponseCode = "response_code"
)

type ResponseRecorder struct {
	HeaderMap http.Header
	Code      int
}

// NewRecorder returns an initialized [ResponseRecorder].
func NewRecorder() *ResponseRecorder {
	return &ResponseRecorder{
		HeaderMap: make(http.Header),
		Code:      0,
	}
}

func (rw *ResponseRecorder) Header() http.Header {
	m := rw.HeaderMap
	if m == nil {
		m = make(http.Header)
		rw.HeaderMap = m
	}
	return m
}

func (rw *ResponseRecorder) Write(buf []byte) (int, error) {
	return len(buf), nil
}

// WriteHeader implements [http.ResponseWriter].
func (rw *ResponseRecorder) WriteHeader(code int) {
	rw.HeaderMap.Add(ResponseCode, string(code))
	rw.Code = code
}

func (rw *ResponseRecorder) GetStatus() int {
	return rw.Code
}
