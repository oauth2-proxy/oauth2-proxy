package upstream

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/app/pagewriter"
	"golang.org/x/net/websocket"
)

func TestUpstreamTLSUsesConfiguredRoot(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer backend.Close()
	cert := backend.Certificate()
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	upstream := options.Upstream{URI: backend.URL, RootCA: &options.SecretSource{Value: root}}
	if err := prepareUpstreamTLS(&upstream, mustParseURL(t, backend.URL)); err != nil {
		t.Fatal(err)
	}
	proxy := newReverseProxy(mustParseURL(t, backend.URL), upstream, nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

func TestUpstreamTLSRejectsPartialClientCertificate(t *testing.T) {
	upstream := options.Upstream{URI: "https://backend", ClientCert: &options.SecretSource{Value: []byte("x")}}
	if err := prepareUpstreamTLS(&upstream, mustParseURL(t, upstream.URI)); err == nil {
		t.Fatal("expected client certificate pair validation error")
	}
}

func TestNewProxyRejectsTLSOptionsOnStaticUpstream(t *testing.T) {
	static := true
	_, err := NewProxy(options.UpstreamConfig{Upstreams: []options.Upstream{{ID: "static", Static: &static, RootCA: &options.SecretSource{Value: []byte("bad")}}}}, nil, &pagewriter.WriterFuncs{})
	if err == nil {
		t.Fatal("expected static upstream TLS configuration error")
	}
}

func TestUpstreamTLSUsesClientCertificate(t *testing.T) {
	caKey, caCert, caPEM := testCertificate(t, true, nil, nil)
	serverKey, serverCert, _ := testCertificate(t, false, caCert, caKey)
	clientKey, clientCert, _ := testCertificate(t, true, caCert, caKey)
	serverTLS := tls.Certificate{Certificate: [][]byte{serverCert.Raw}, PrivateKey: serverKey}
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	backend.TLS = &tls.Config{Certificates: []tls.Certificate{serverTLS}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
	backend.TLS.ClientCAs.AppendCertsFromPEM(caPEM)
	backend.StartTLS()
	defer backend.Close()

	upstream := options.Upstream{URI: backend.URL, RootCA: &options.SecretSource{Value: caPEM}, ClientCert: &options.SecretSource{Value: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw})}, ClientKey: &options.SecretSource{Value: pem.EncodeToMemory(pemBlockForKey(clientKey))}}
	u := mustParseURL(t, backend.URL)
	if err := prepareUpstreamTLS(&upstream, u); err != nil {
		t.Fatal(err)
	}
	proxy := newReverseProxy(u, upstream, nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

func TestUpstreamTLSRejectsUntrustedServer(t *testing.T) {
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("unexpected")) }))
	defer backend.Close()
	u := mustParseURL(t, backend.URL)
	upstream := options.Upstream{URI: backend.URL}
	proxy := newReverseProxy(u, upstream, nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code == http.StatusOK {
		t.Fatal("unexpected successful request to untrusted server")
	}
}

func TestUpstreamTLSKeepsPerUpstreamTrustIsolated(t *testing.T) {
	first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("first")) }))
	defer first.Close()
	second := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("second")) }))
	defer second.Close()
	makeProxy := func(backend *httptest.Server) http.Handler {
		u := mustParseURL(t, backend.URL)
		upstream := options.Upstream{URI: backend.URL, RootCA: &options.SecretSource{Value: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.Certificate().Raw})}}
		if err := prepareUpstreamTLS(&upstream, u); err != nil {
			t.Fatal(err)
		}
		return newReverseProxy(u, upstream, nil)
	}
	for _, tc := range []struct {
		proxy http.Handler
		want  string
	}{{makeProxy(first), "first"}, {makeProxy(second), "second"}} {
		rec := httptest.NewRecorder()
		tc.proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Body.String() != tc.want {
			t.Fatalf("got %q, want %q", rec.Body.String(), tc.want)
		}
	}
}

func TestWebSocketProxyUsesClientCertificate(t *testing.T) {
	caKey, caCert, caPEM := testCertificate(t, true, nil, nil)
	serverKey, serverCert, _ := testCertificate(t, false, caCert, caKey)
	clientKey, clientCert, _ := testCertificate(t, true, caCert, caKey)
	backend := httptest.NewUnstartedServer(websocket.Handler(func(ws *websocket.Conn) {
		var msg string
		_ = websocket.Message.Receive(ws, &msg)
		_ = websocket.Message.Send(ws, msg)
	}))
	backend.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{serverCert.Raw}, PrivateKey: serverKey}}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
	backend.TLS.ClientCAs.AppendCertsFromPEM(caPEM)
	backend.StartTLS()
	defer backend.Close()
	u := mustParseURL(t, backend.URL)
	upstream := options.Upstream{URI: backend.URL, RootCA: &options.SecretSource{Value: caPEM}, ClientCert: &options.SecretSource{Value: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw})}, ClientKey: &options.SecretSource{Value: pem.EncodeToMemory(pemBlockForKey(clientKey))}}
	if err := prepareUpstreamTLS(&upstream, u); err != nil {
		t.Fatal(err)
	}
	frontend := httptest.NewServer(newWebSocketReverseProxy(u, nil, nil, upstream.TLSClientConfig()))
	defer frontend.Close()
	wsURL := "ws" + strings.TrimPrefix(frontend.URL, "http")
	ws, err := websocket.Dial(wsURL, "", frontend.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	if err := websocket.Message.Send(ws, "hello"); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := websocket.Message.Receive(ws, &got); err != nil {
		t.Fatal(err)
	}
	if got != "hello" {
		t.Fatalf("got %q", got)
	}
}

func testCertificate(t *testing.T, client bool, signer *x509.Certificate, signerKey *rsa.PrivateKey) (*rsa.PrivateKey, *x509.Certificate, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: signer == nil, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	if signer == nil {
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	if signer != nil {
		if client {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tmpl.DNSNames = []string{"127.0.0.1", "localhost"}
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
	}
	parent := tmpl
	issuerKey := signerKey
	if signer != nil {
		parent = signer
	} else {
		issuerKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func pemBlockForKey(key *rsa.PrivateKey) *pem.Block {
	return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
