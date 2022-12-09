package types

import "net/http"

// Tenant Loader
// currently only implementation is configLoader, which loads the tenants from configuration file, doesn't support adding/removing tenants dynamically
type Loader interface {
	Load(req *http.Request) (*Tenant, error)
	LoadById(id string) (*Tenant, error)
}
