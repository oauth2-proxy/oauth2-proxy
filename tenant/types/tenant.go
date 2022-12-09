package types

import (
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

type Tenant struct {
	Id       string
	Provider providers.Provider
}
