package middleware

import (
	"net/http"
	"time"
)

type ResponseTimer interface {
	Start()
	Duration() (time.Duration, error)
}

type ResponseMetadata interface {
	SetMetadata(key interface{}, value interface{})
	GetMetadata(key interface{}) interface{}
}

type ResponseWriter interface {
	http.ResponseWriter
	http.Hijacker
	http.Flusher

	ResponseTimer
	ResponseMetadata

	Status() int
	Size() int
}
