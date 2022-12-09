package configloader

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	"github.com/oauth2-proxy/oauth2-proxy/v7/tenant/types"
	"github.com/spf13/viper"
)

type loader struct {
	conf        *Configuration           // tenant loader configuration
	tenantsConf *TenantsConfig           // tenants configuration that has been loaded from file at path loader.conf.TenantsFile
	tenants     map[string]*types.Tenant // tenants map, key is tenant id

	rules []*rule
}

func New(conf *Configuration) (*loader, error) {
	tntsConf := &TenantsConfig{}

	err := loadConfigFromFile(conf.TenantsFile, tntsConf)
	if err != nil {
		return nil, fmt.Errorf("unable to load tenants cofig from file: %w", err)
	}

	loader := &loader{
		conf:        conf,
		tenantsConf: tntsConf,
	}
	loader.tenants = make(map[string]*types.Tenant)

	for _, tntConf := range tntsConf.Tenants {
		tnt, err := tenantFromTenantConfig(tntConf)
		if err != nil {
			return nil, fmt.Errorf("invalid tenant config: %w", err)
		}
		loader.tenants[tnt.Id] = tnt
	}

	for _, ruleConf := range conf.Rules {
		rule, err := newRule(*ruleConf)
		if err != nil {
			return nil, fmt.Errorf("unable to create new rule: %w", err)
		}
		loader.rules = append(loader.rules, rule)
	}

	return loader, nil
}

func tenantFromTenantConfig(tntConf *TenantConfig) (*types.Tenant, error) {
	provider, err := providers.NewProvider(*tntConf.Provider)
	if err != nil {
		return nil, fmt.Errorf("invalid provider config: %w", err)
	}
	return &types.Tenant{
		Id:       tntConf.Id,
		Provider: provider,
	}, nil
}

func (l *loader) LoadById(id string) (*types.Tenant, error) {
	if tnt, ok := l.tenants[id]; ok {
		return tnt, nil
	} else {
		return nil, fmt.Errorf("no tenant found with id='%s'", id)
	}
}

func (l *loader) Load(req *http.Request) (*types.Tenant, error) {

	// we go through all rules, and if a rule extracts a tenant id from the request, we return the correspoding tenant
	// if no tenant exists with the extracted id, we move to the next rule

	for _, rule := range l.rules {
		id := rule.execute(req)
		if id != "" {
			if tnt, ok := l.tenants[id]; ok {
				return tnt, nil
			}
		}
	}

	return nil, fmt.Errorf("could not load tenant from request")
}

// loads the tenants from tenants' config file into &TenantsConfig{} struct
func loadConfigFromFile(configPath string, c interface{}) error {
	v := viper.New()
	v.SetConfigFile(configPath)
	v.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	v.SetEnvKeyReplacer(replacer)

	err := v.ReadInConfig()
	if err != nil {
		return err
	}
	err = v.Unmarshal(&c)

	if err == nil {
		jsonConfig, _ := json.MarshalIndent(&c, "", "  ")
		log.Printf("loaded config :\n%s\n", string(jsonConfig))
	}

	return err
}
