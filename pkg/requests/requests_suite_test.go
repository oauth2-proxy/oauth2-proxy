package requests

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	server     *httptest.Server
	serverAddr string
)

func TestRequetsSuite(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)
	log.SetOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Requests Suite")
}

var _ = BeforeSuite(func() {
	// Set up a webserver that reflects requests
	mux := http.NewServeMux()
	mux.Handle("/json/", &testHTTPUpstream{})
	mux.HandleFunc("/string/", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Write([]byte("OK"))
	})
	server = httptest.NewServer(mux)
	serverAddr = fmt.Sprintf("http://%s", server.Listener.Addr().String())
})

var _ = AfterSuite(func() {
	server.Close()
})

// testHTTPRequest is a struct used to capture the state of a request made to
// the test server
type testHTTPRequest struct {
	Method     string
	Header     http.Header
	Body       []byte
	RequestURI string
}

type testHTTPUpstream struct{}

func (t *testHTTPUpstream) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	request, err := toTestHTTPRequest(req)
	if err != nil {
		t.writeError(rw, err)
		return
	}

	data, err := json.Marshal(request)
	if err != nil {
		t.writeError(rw, err)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Write(data)
}

func (t *testHTTPUpstream) writeError(rw http.ResponseWriter, err error) {
	rw.WriteHeader(500)
	if err != nil {
		rw.Write([]byte(err.Error()))
	}
}

func toTestHTTPRequest(req *http.Request) (testHTTPRequest, error) {
	requestBody := []byte{}
	if req.Body != http.NoBody {
		var err error
		requestBody, err = io.ReadAll(req.Body)
		if err != nil {
			return testHTTPRequest{}, err
		}
	}

	return testHTTPRequest{
		Method:     req.Method,
		Header:     req.Header,
		Body:       requestBody,
		RequestURI: req.RequestURI,
	}, nil
}
