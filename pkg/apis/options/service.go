package options

import (
	"errors"

	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
)

// Cookie contains configuration options relating to Service configuration
type Service struct {
	// 带服务类型的完整 FQDN 名称，例如 keycloak.static, auth.dns
	ServiceName string `mapstructure:"service_name"`
	ServicePort int64  `mapstructure:"service_port"`
	ServiceHost string `mapstructure:"service_host"`
}

func (s *Service) NewService() (wrapper.HttpClient, error) {
	if s.ServiceName == "" || s.ServicePort == 0 {
		return nil, errors.New("invalid service config")
	}
	client := wrapper.NewClusterClient(&wrapper.FQDNCluster{
		FQDN: s.ServiceName,
		Host: s.ServiceHost,
		Port: s.ServicePort,
	})
	return client, nil
}

type ValidateService struct {
	// 带服务类型的完整 FQDN 名称，例如 keycloak.static, auth.dns
	ServiceName string `mapstructure:"validate_service_name"`
	ServicePort int64  `mapstructure:"validate_service_port"`
	ServiceHost string `mapstructure:"validate_service_host"`
}

func (s *ValidateService) NewService() (wrapper.HttpClient, error) {
	if s.ServiceName == "" || s.ServicePort == 0 {
		return nil, errors.New("invalid service config")
	}
	client := wrapper.NewClusterClient(&wrapper.FQDNCluster{
		FQDN: s.ServiceName,
		Host: s.ServiceHost,
		Port: s.ServicePort,
	})
	return client, nil
}
