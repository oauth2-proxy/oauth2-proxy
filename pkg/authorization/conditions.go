package authorization

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
)

type condition interface {
	matches(*http.Request) bool
}

type methodCondition struct {
	methods map[string]struct{}
}

func (m methodCondition) matches(req *http.Request) bool {
	_, ok := m.methods[strings.ToUpper(req.Method)]
	return ok
}

func newMethodCondition(methods []string) condition {
	methodMap := make(map[string]struct{})
	for _, method := range methods {
		methodMap[strings.ToUpper(method)] = struct{}{}
	}
	return methodCondition{
		methods: methodMap,
	}
}

type pathCondition struct {
	pathRegexp *regexp.Regexp
}

func (p pathCondition) matches(req *http.Request) bool {
	return p.pathRegexp.MatchString(req.URL.Path)
}

func newPathCondition(path string) (condition, error) {
	exp, err := regexp.Compile(path)
	if err != nil {
		return nil, err
	}
	return pathCondition{
		pathRegexp: exp,
	}, nil
}

type ipCondition struct {
	netSet      *ip.NetSet
	getClientIP func(req *http.Request) net.IP
}

func (i ipCondition) matches(req *http.Request) bool {
	ip := i.getClientIP(req)
	if ip == nil {
		return false
	}
	return i.netSet.Has(ip)
}

func newIPCondition(rawIPs []string, getClientIPFunc func(req *http.Request) net.IP) (condition, error) {
	if getClientIPFunc == nil {
		return nil, errors.New("client IP function required for IP condition")
	}

	netSet := ip.NewNetSet()
	for _, rawIP := range rawIPs {
		ipNet := ip.ParseIPNet(rawIP)
		if ipNet == nil {
			return nil, fmt.Errorf("could not parse IP network: %s", rawIP)
		}
		netSet.AddIPNet(*ipNet)
	}

	return ipCondition{
		netSet:      netSet,
		getClientIP: getClientIPFunc,
	}, nil
}
