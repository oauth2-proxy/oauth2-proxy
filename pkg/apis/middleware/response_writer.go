package middleware

import (
	"net/http"
)

// ResponseWriter wraps an http.ResponseWriter and supports subsequent access
// to the HTTP status and size of the response body.
type ResponseWriter interface {
	http.ResponseWriter
	http.Hijacker
	http.Flusher

	Status() int
	Size() int
}
