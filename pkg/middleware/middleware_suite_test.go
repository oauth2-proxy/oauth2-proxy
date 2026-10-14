package middleware

import (
	"net/http"
	"testing"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestMiddlewareSuite(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Middleware")
}

func testHandler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(200)
		rw.Write([]byte("test"))
	})
}

func testUpstreamHandler(upstream string) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)
		scope.Upstream = upstream

		rw.WriteHeader(200)
		rw.Write([]byte("test"))
	})
}
