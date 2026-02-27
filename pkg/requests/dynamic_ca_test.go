package requests

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCert creates a self-signed certificate for testing
func generateTestCert(t *testing.T, commonName string) (certPEM []byte) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return certPEM
}

// createTempCAFile creates a temporary CA file for testing
func createTempCAFile(t *testing.T, dir string, certPEM []byte) string {
	t.Helper()

	file, err := os.CreateTemp(dir, "ca-*.pem")
	require.NoError(t, err)

	_, err = file.Write(certPEM)
	require.NoError(t, err)
	require.NoError(t, file.Close())

	return file.Name()
}

func TestNewDynamicCALoader(t *testing.T) {
	tempDir := t.TempDir()
	certPEM := generateTestCert(t, "Test CA")
	caFile := createTempCAFile(t, tempDir, certPEM)

	loader, err := NewDynamicCALoader([]string{caFile}, false)
	require.NoError(t, err)
	require.NotNil(t, loader)

	pool, err := loader.GetCertPool()
	require.NoError(t, err)
	require.NotNil(t, pool)
}

func TestNewDynamicCALoader_InvalidFile(t *testing.T) {
	loader, err := NewDynamicCALoader([]string{"/nonexistent/ca.pem"}, false)
	assert.Error(t, err)
	assert.Nil(t, loader)
}

func TestNewDynamicCALoader_EmptyFiles(t *testing.T) {
	loader, err := NewDynamicCALoader([]string{}, false)
	assert.Error(t, err)
	assert.Nil(t, loader)
}

func TestDynamicCALoader_GetCertPool_ReturnsCached(t *testing.T) {
	tempDir := t.TempDir()
	certPEM := generateTestCert(t, "Test CA")
	caFile := createTempCAFile(t, tempDir, certPEM)

	loader, err := NewDynamicCALoader([]string{caFile}, false)
	require.NoError(t, err)

	// Multiple calls should return the same cached pool
	pool1, err := loader.GetCertPool()
	require.NoError(t, err)

	pool2, err := loader.GetCertPool()
	require.NoError(t, err)

	// Both should be the same pointer (cached)
	assert.Same(t, pool1, pool2)
}

func TestDynamicCALoader_ForceReload(t *testing.T) {
	tempDir := t.TempDir()
	certPEM := generateTestCert(t, "Test CA")
	caFile := createTempCAFile(t, tempDir, certPEM)

	loader, err := NewDynamicCALoader([]string{caFile}, false)
	require.NoError(t, err)

	pool1, err := loader.GetCertPool()
	require.NoError(t, err)

	// Update the file with new cert
	newCertPEM := generateTestCert(t, "New Test CA")
	err = os.WriteFile(caFile, newCertPEM, 0600)
	require.NoError(t, err)

	// Force reload
	loader.ForceReload()

	pool2, err := loader.GetCertPool()
	require.NoError(t, err)

	// Pools should be different after reload
	assert.NotSame(t, pool1, pool2)
}

func TestDynamicCALoader_ForceReload_ErrorKeepsOldCerts(t *testing.T) {
	tempDir := t.TempDir()
	certPEM := generateTestCert(t, "Test CA")
	caFile := createTempCAFile(t, tempDir, certPEM)

	loader, err := NewDynamicCALoader([]string{caFile}, false)
	require.NoError(t, err)

	pool1, err := loader.GetCertPool()
	require.NoError(t, err)

	// Delete the file to cause reload error
	err = os.Remove(caFile)
	require.NoError(t, err)

	// ForceReload should fail but keep old certs
	loader.ForceReload()

	// GetCertPool should still return the old pool
	pool2, err := loader.GetCertPool()
	require.NoError(t, err)
	assert.Same(t, pool1, pool2)
}

func TestDynamicCALoader_MultipleCertFiles(t *testing.T) {
	tempDir := t.TempDir()

	cert1PEM := generateTestCert(t, "Test CA 1")
	cert2PEM := generateTestCert(t, "Test CA 2")

	caFile1 := createTempCAFile(t, tempDir, cert1PEM)
	caFile2 := createTempCAFile(t, tempDir, cert2PEM)

	loader, err := NewDynamicCALoader([]string{caFile1, caFile2}, false)
	require.NoError(t, err)

	pool, err := loader.GetCertPool()
	require.NoError(t, err)
	require.NotNil(t, pool)
}

func TestDynamicTLSTransport_Creation(t *testing.T) {
	tempDir := t.TempDir()
	certPEM := generateTestCert(t, "Test CA")
	caFile := createTempCAFile(t, tempDir, certPEM)

	loader, err := NewDynamicCALoader([]string{caFile}, false)
	require.NoError(t, err)

	transport := NewDynamicTLSTransport(loader)
	require.NotNil(t, transport)
	require.NotNil(t, transport.base)
	require.NotNil(t, transport.base.TLSClientConfig)
}

func TestDynamicCALoader_StartWatching(t *testing.T) {
	tempDir := t.TempDir()
	certPEM := generateTestCert(t, "Test CA")
	caFile := filepath.Join(tempDir, "ca.pem")
	err := os.WriteFile(caFile, certPEM, 0600)
	require.NoError(t, err)

	loader, err := NewDynamicCALoader([]string{caFile}, false)
	require.NoError(t, err)

	done := make(chan bool)
	defer close(done)

	err = loader.StartWatching(done)
	require.NoError(t, err)

	// Give watcher time to start
	time.Sleep(100 * time.Millisecond)

	pool1, err := loader.GetCertPool()
	require.NoError(t, err)

	// Update the file
	newCertPEM := generateTestCert(t, "New Test CA")
	err = os.WriteFile(caFile, newCertPEM, 0600)
	require.NoError(t, err)

	// Give watcher time to detect and reload
	time.Sleep(200 * time.Millisecond)

	pool2, err := loader.GetCertPool()
	require.NoError(t, err)

	// After file change, the pool should be reloaded
	assert.NotSame(t, pool1, pool2)
}
