package upstream

import (
	"net/http"
	"net/http/httptest"
)

type requestFactory func() *http.Request

func requestFactoryGet(target string) requestFactory {
	return func() *http.Request {
		return httptest.NewRequest("", target, nil)
	}
}
