package upstream

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/net/websocket"
)

var (
	filesDir       string
	server         *httptest.Server
	serverAddr     string
	unixServer     *httptest.Server
	unixServerAddr string
	invalidServer  = "http://::1"
)

func TestUpstreamSuite(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)
	log.SetOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Upstream Suite")
}

var _ = BeforeSuite(func() {
	// Set up files for serving via file servers
	dir, err := os.MkdirTemp("", "oauth2-proxy-upstream-suite")
	Expect(err).ToNot(HaveOccurred())
	Expect(os.WriteFile(path.Join(dir, "foo"), []byte("foo"), 0644)).To(Succeed())
	Expect(os.WriteFile(path.Join(dir, "bar"), []byte("bar"), 0644)).To(Succeed())
	Expect(os.Mkdir(path.Join(dir, "subdir"), os.ModePerm)).To(Succeed())
	Expect(os.WriteFile(path.Join(dir, "subdir", "baz"), []byte("baz"), 0644)).To(Succeed())
	filesDir = dir

	// Set up a webserver that reflects requests
	server = httptest.NewServer(&testHTTPUpstream{})
	serverAddr = fmt.Sprintf("http://%s", server.Listener.Addr().String())

	unixServer = httptest.NewUnstartedServer(&testHTTPUpstream{})
	unixListener, _ := net.Listen("unix", path.Join(filesDir, "test.sock"))
	unixServer.Listener = unixListener
	unixServer.Start()
	unixServerAddr = fmt.Sprintf("unix://%s", path.Join(filesDir, "test.sock"))
})

var _ = AfterSuite(func() {
	server.Close()
	unixServer.Close()
	Expect(os.RemoveAll(filesDir)).To(Succeed())
})

const (
	contentType     = "Content-Type"
	contentLength   = "Content-Length"
	acceptEncoding  = "Accept-Encoding"
	applicationJSON = "application/json"
	textPlainUTF8   = "text/plain; charset=utf-8"
	textHTMLUTF8    = "text/html; charset=utf-8"
	gapAuth         = "Gap-Auth"
	gapSignature    = "Gap-Signature"
)

// testHTTPResponse is a struct used for checking responses in table tests
type testHTTPResponse struct {
	code    int
	header  http.Header
	raw     string
	request testHTTPRequest
}

// testHTTPRequest is a struct used to capture the state of a request made to
// an upstream during a test
type testHTTPRequest struct {
	Method     string
	URL        string
	Header     http.Header
	Body       []byte
	Host       string
	RequestURI string
}

type testWebSocketResponse struct {
	Message string
	Origin  string
}

type testHTTPUpstream struct{}

func (t *testHTTPUpstream) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Upgrade") == "websocket" {
		t.websocketHandler().ServeHTTP(rw, req)
	} else {
		t.serveHTTP(rw, req)
	}
}

func (t *testHTTPUpstream) serveHTTP(rw http.ResponseWriter, req *http.Request) {
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

func (t *testHTTPUpstream) websocketHandler() http.Handler {
	return websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		var data []byte
		err := websocket.Message.Receive(ws, &data)
		if err != nil {
			websocket.Message.Send(ws, []byte(err.Error()))
			return
		}

		wsResponse := testWebSocketResponse{
			Message: string(data),
			Origin:  ws.Request().Header.Get("Origin"),
		}
		err = websocket.JSON.Send(ws, wsResponse)
		if err != nil {
			websocket.Message.Send(ws, []byte(err.Error()))
			return
		}
	})
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
		URL:        req.URL.String(),
		Header:     req.Header,
		Body:       requestBody,
		Host:       req.Host,
		RequestURI: req.RequestURI,
	}, nil
}

// String headers added to the response that we do not want to test
func testSanitizeResponseHeader(h http.Header) {
	// From HTTP responses
	h.Del("Date")
	h.Del(contentLength)

	// From File responses
	h.Del("Accept-Ranges")
	h.Del("Last-Modified")
}

// Strip the accept header that is added by the HTTP Transport
func testSanitizeRequestHeader(h http.Header) {
	h.Del(acceptEncoding)
}
