package header

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options/util"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

type Injector interface {
	Inject(http.Header, *sessionsapi.SessionState)
}

type injector struct {
	valueInjectors []valueInjector
}

func (i injector) Inject(header http.Header, session *sessionsapi.SessionState) {
	for _, injector := range i.valueInjectors {
		injector.inject(header, session)
	}
}

func NewInjector(headers []options.Header) (Injector, error) {
	injectors := []valueInjector{}
	for _, header := range headers {
		for _, value := range header.Values {
			injector, err := newValueinjector(header.Name, value)
			if err != nil {
				return nil, fmt.Errorf("error building injector for header %q: %v", header.Name, err)
			}
			injectors = append(injectors, injector)
		}
	}

	return &injector{valueInjectors: injectors}, nil
}

func updateHeaderWithClaimValues(header *http.Header, name string, claimValues []string, prefix string) {
	if len(claimValues) == 0 {
		return
	}
	nonEmptyValues := make([]string, 0)
	existingValues := header.Values(name)
	if len(existingValues) > 0 {
		nonEmptyValues = append(nonEmptyValues, strings.Join(existingValues, ","))
	}
	for _, claim := range claimValues {
		if claim != "" {
			nonEmptyValues = append(nonEmptyValues, prefix+claim)
		}
	}
	if len(nonEmptyValues) > 0 {
		header.Set(name, strings.Join(nonEmptyValues, ","))
	}

}

type valueInjector interface {
	inject(http.Header, *sessionsapi.SessionState)
}

func newValueinjector(name string, value options.HeaderValue) (valueInjector, error) {
	switch {
	case value.SecretSource != nil && value.ClaimSource == nil:
		return newSecretInjector(name, value.SecretSource)
	case value.SecretSource == nil && value.ClaimSource != nil:
		return newClaimInjector(name, value.ClaimSource)
	default:
		return nil, fmt.Errorf("header %q value has multiple entries: only one entry per value is allowed", name)
	}
}

type injectorFunc struct {
	injectFunc func(http.Header, *sessionsapi.SessionState)
}

func (i *injectorFunc) inject(header http.Header, session *sessionsapi.SessionState) {
	i.injectFunc(header, session)
}

func newInjectorFunc(injectFunc func(header http.Header, session *sessionsapi.SessionState)) valueInjector {
	return &injectorFunc{injectFunc: injectFunc}
}

func newSecretInjector(name string, source *options.SecretSource) (valueInjector, error) {
	value, err := util.GetSecretValue(source)
	if err != nil {
		return nil, fmt.Errorf("error getting secret value: %v", err)
	}

	return newInjectorFunc(func(header http.Header, session *sessionsapi.SessionState) {
		header.Add(name, string(value))
	}), nil
}

func newClaimInjector(name string, source *options.ClaimSource) (valueInjector, error) {
	switch {
	case source.BasicAuthPassword != nil:
		password, err := util.GetSecretValue(source.BasicAuthPassword)
		if err != nil {
			return nil, fmt.Errorf("error loading basicAuthPassword: %v", err)
		}
		return newInjectorFunc(func(header http.Header, session *sessionsapi.SessionState) {
			claimValues := session.GetClaim(source.Claim)
			for _, claim := range claimValues {
				if claim == "" {
					continue
				}
				auth := claim + ":" + string(password)
				header.Add(name, "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
			}
		}), nil
	default:
		return newInjectorFunc(func(header http.Header, session *sessionsapi.SessionState) {
			claimValues := session.GetClaim(source.Claim)
			updateHeaderWithClaimValues(&header, name, claimValues, source.Prefix)
		}), nil
	}
}
