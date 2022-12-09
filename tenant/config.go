package tenant

import (
	"github.com/oauth2-proxy/oauth2-proxy/v7/tenant/configloader"
	"github.com/oauth2-proxy/oauth2-proxy/v7/tenant/single"
)

type LoaderConfiguration struct {
	Type   string
	Config *configloader.Configuration
	Single *single.Configuration
}
