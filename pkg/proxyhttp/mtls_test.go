package proxyhttp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	"github.com/stretchr/testify/require"
)

func TestClientCertificateAuthentication(t *testing.T) {
	serverDER, serverKey, err := util.GenerateCert("127.0.0.1")
	require.NoError(t, err)
	serverCert := &options.SecretSource{Value: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})}
	serverPrivateKey := &options.SecretSource{Value: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKey})}
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(serverCert.Value))
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	client := func(issuer *x509.Certificate, key ed25519.PrivateKey, expired bool, usage x509.ExtKeyUsage) tls.Certificate {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		expiry := time.Now().Add(time.Hour)
		if expired {
			expiry = time.Now().Add(-time.Minute)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, cert, issuer, pub, key)
		require.NoError(t, err)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
	}
	trusted := client(ca, caKey, false, x509.ExtKeyUsageClientAuth)
	expired := client(ca, caKey, true, x509.ExtKeyUsageClientAuth)
	wrongUsage := client(ca, caKey, false, x509.ExtKeyUsageServerAuth)
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	untrusted := client(ca, otherKey, false, x509.ExtKeyUsageClientAuth)
	for _, tc := range []struct {
		name    string
		mtls    bool
		cert    *tls.Certificate
		allowed bool
	}{
		{"HTTPS remains opt-in client auth", false, nil, true},
		{"trusted", true, &trusted, true}, {"missing", true, nil, false},
		{"untrusted", true, &untrusted, false}, {"expired", true, &expired, false}, {"wrong usage", true, &wrongUsage, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tlsOpts := &options.TLS{Cert: serverCert, Key: serverPrivateKey}
			if tc.mtls {
				tlsOpts.ClientCA = &options.SecretSource{Value: caPEM}
			}
			s := &server{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })}
			require.NoError(t, s.setupTLSListener(Opts{SecureBindAddress: "127.0.0.1:0", TLS: tlsOpts}))
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- s.Start(ctx) }()
			t.Cleanup(func() { cancel(); require.NoError(t, <-done) })
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
			if tc.cert != nil {
				transport.TLSClientConfig.Certificates = []tls.Certificate{*tc.cert}
			}
			defer transport.CloseIdleConnections()
			c := &http.Client{Transport: transport, Timeout: time.Second * 5}
			resp, err := c.Get("https://" + s.tlsListener.Addr().String())
			if !tc.allowed {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusNoContent, resp.StatusCode)
		})
	}
	for _, tc := range []struct {
		name    string
		opts    Opts
		message string
	}{
		{"no HTTPS", Opts{TLS: &options.TLS{ClientCA: &options.SecretSource{Value: caPEM}}}, "requires an HTTPS listener"},
		{"plaintext bypass", Opts{BindAddress: "127.0.0.1:0", SecureBindAddress: "127.0.0.1:0", TLS: &options.TLS{ClientCA: &options.SecretSource{Value: caPEM}}}, "HTTP listener must be disabled"},
		{"missing server certificate", Opts{SecureBindAddress: "127.0.0.1:0", TLS: &options.TLS{ClientCA: &options.SecretSource{Value: caPEM}}}, "could not load certificate"},
		{"empty CA", Opts{SecureBindAddress: "127.0.0.1:0", TLS: &options.TLS{Cert: serverCert, Key: serverPrivateKey, ClientCA: &options.SecretSource{}}}, "could not load client CA"},
		{"invalid CA", Opts{SecureBindAddress: "127.0.0.1:0", TLS: &options.TLS{Cert: serverCert, Key: serverPrivateKey, ClientCA: &options.SecretSource{Value: []byte("invalid")}}}, "no valid PEM certificates"},
		{"unreadable CA", Opts{SecureBindAddress: "127.0.0.1:0", TLS: &options.TLS{Cert: serverCert, Key: serverPrivateKey, ClientCA: &options.SecretSource{FromFile: filepath.Join(t.TempDir(), "missing")}}}, "could not load client CA"},
	} {
		t.Run(tc.name, func(t *testing.T) { _, err := NewServer(tc.opts); require.ErrorContains(t, err, tc.message) })
	}
	// Configuration errors must release any plaintext listener opened during setup.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	_, err = NewServer(Opts{BindAddress: address, SecureBindAddress: "127.0.0.1:0"})
	require.Error(t, err)
	listener, err = net.Listen("tcp", address)
	require.NoError(t, err)
	require.NoError(t, listener.Close())
}
