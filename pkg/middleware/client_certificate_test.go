package middleware

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/stretchr/testify/require"
)

func TestClientCertificateSessionLoader(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("certificate"), SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client"}, NotAfter: time.Now().Add(time.Hour)}
	digest := sha256.Sum256(cert.Raw)
	loader := NewClientCertificateSessionLoader([]options.ClientIdentity{{Fingerprint: hex.EncodeToString(digest[:]), User: "client", Email: "client@example.com", Groups: []string{"operators"}}})

	t.Run("mapped certificate creates request session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
		rw := httptest.NewRecorder()
		loader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s := middlewareapi.GetRequestScope(r).Session
			require.NotNil(t, s.CreatedAt)
			require.WithinDuration(t, time.Now(), *s.CreatedAt, time.Second)
			require.Equal(t, cert.NotAfter, *s.ExpiresOn)
			require.Equal(t, "client", s.User)
			require.Equal(t, "client@example.com", s.Email)
			require.Equal(t, []string{"operators"}, s.Groups)
			require.Empty(t, r.Cookies())
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(rw, req)
		require.Equal(t, http.StatusNoContent, rw.Code)
	})

	t.Run("no certificate falls through", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})
		rw := httptest.NewRecorder()
		loader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Nil(t, middlewareapi.GetRequestScope(r).Session)
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(rw, req)
		require.Equal(t, http.StatusNoContent, rw.Code)
	})

	t.Run("unmapped certificate is forbidden", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{&x509.Certificate{Raw: []byte("other"), NotAfter: time.Now().Add(time.Hour)}}}}
		rw := httptest.NewRecorder()
		loader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("unmapped certificate reached handler") })).ServeHTTP(rw, req)
		require.Equal(t, http.StatusForbidden, rw.Code)
	})
}

func TestClientCertificateSessionChainValidity(t *testing.T) {
	now := time.Now()
	leaf := &x509.Certificate{Raw: []byte("leaf"), NotAfter: now.Add(time.Hour)}
	digest := sha256.Sum256(leaf.Raw)
	loader := NewClientCertificateSessionLoader([]options.ClientIdentity{{Fingerprint: hex.EncodeToString(digest[:]), User: "client"}})
	for _, position := range []string{"intermediate", "root"} {
		t.Run(position, func(t *testing.T) {
			issuer := &x509.Certificate{NotAfter: now.Add(time.Minute)}
			chain := []*x509.Certificate{leaf, issuer}
			if position == "root" {
				chain = []*x509.Certificate{leaf, {NotAfter: leaf.NotAfter}, issuer}
			}
			req := middlewareapi.AddRequestScope(httptest.NewRequest(http.MethodGet, "/", nil), &middlewareapi.RequestScope{})
			req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{chain}}
			rw := httptest.NewRecorder()
			loader(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, issuer.NotAfter, *middlewareapi.GetRequestScope(r).Session.ExpiresOn)
				w.WriteHeader(http.StatusNoContent)
			})).ServeHTTP(rw, req)
			require.Equal(t, http.StatusNoContent, rw.Code)
			// A reused TLS connection must not retain authentication after an issuer expires.
			issuer.NotAfter = now.Add(-time.Minute)
			req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{})
			rw = httptest.NewRecorder()
			loader(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("expired chain reached handler") })).ServeHTTP(rw, req)
			require.Equal(t, http.StatusForbidden, rw.Code)
		})
	}
}
