package configloader

import (
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options/provideropts"
)

// configuration for the tenantLoader implementation (configloader)
type Configuration struct {
	TenantsFile string // path to the tenant's config file
	Rules       []*RuleConfig
}

// structure that is loaded from the tenant's config file
type TenantsConfig struct {
	Tenants []*TenantConfig
}

// configuration of a single tenant
type TenantConfig struct {
	Id       string
	Provider *provideropts.Provider
}
