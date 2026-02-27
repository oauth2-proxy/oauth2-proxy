package requests

import (
	"crypto/x509"
	"sync/atomic"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/watcher"
)

// DynamicCALoader provides hot-reloadable CA certificates.
// It caches the certificate pool and reloads from disk when triggered
// by file system events via the watcher.
type DynamicCALoader struct {
	caFiles             []string
	useSystemTrustStore bool
	certPool            atomic.Pointer[x509.CertPool]
}

// NewDynamicCALoader creates a new DynamicCALoader that loads CA certificates
// from the specified files. The certificates are reloaded automatically when
// files change on disk.
func NewDynamicCALoader(caFiles []string, useSystemTrustStore bool) (*DynamicCALoader, error) {
	d := &DynamicCALoader{
		caFiles:             caFiles,
		useSystemTrustStore: useSystemTrustStore,
	}
	if err := d.reload(); err != nil {
		return nil, err
	}
	return d, nil
}

// GetCertPool returns the current CA certificate pool.
func (d *DynamicCALoader) GetCertPool() (*x509.CertPool, error) {
	return d.certPool.Load(), nil
}

// reload loads CA certificates from disk and updates the cached pool.
func (d *DynamicCALoader) reload() error {
	pool, err := util.GetCertPool(d.caFiles, d.useSystemTrustStore)
	if err != nil {
		return err
	}
	d.certPool.Store(pool)
	logger.Printf("CA certificates reloaded from %v", d.caFiles)
	return nil
}

// ForceReload forces immediate reload of CA certificates.
// This is called by file watcher when CA files change on disk.
func (d *DynamicCALoader) ForceReload() {
	if err := d.reload(); err != nil {
		logger.Errorf("CA reload failed: %v", err)
	}
}

// StartWatching sets up file watchers for all CA files.
// When any CA file changes, the certificates are automatically reloaded.
// This supports Kubernetes ConfigMap/Secret mounts which use symlink replacement.
func (d *DynamicCALoader) StartWatching(done <-chan bool) error {
	for _, caFile := range d.caFiles {
		if err := watcher.WatchFileForUpdates(caFile, done, d.ForceReload); err != nil {
			return err
		}
	}
	return nil
}
