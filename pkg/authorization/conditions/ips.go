package conditions

import (
	"fmt"
	"net/http"
	"strings"

	ipapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/ip"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/ip"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
)

type ips struct {
	ips      *ip.NetSet
	ipParser ipapi.RealClientIPParser
}

// NewIPs takes trusted IPs and builds a unified ip.NetSet to use as a
// authorization.Condition
func NewIPs(trustedIPs []string, parser ipapi.RealClientIPParser) (Condition, error) {
	ns := ip.NewNetSet()
	var failed []string
	failed = nil
	for _, trustedIP := range trustedIPs {
		if ipNet := ip.ParseIPNet(trustedIP); ipNet != nil {
			ns.AddIPNet(*ipNet)
		} else {
			failed = append(failed, trustedIP)
		}
	}
	if failed != nil {
		return nil, fmt.Errorf("could not parse trusted IP network(s): %s", strings.Join(failed, ", "))
	}
	return &ips{
		ips:      ns,
		ipParser: parser,
	}, nil
}

// Match checks if the request remote IP is in the ip.NetSet
// This is reverse proxy aware if an ipParser is set.
func (i *ips) Match(req *http.Request, _ *sessions.SessionState) bool {
	if req == nil {
		return false
	}
	remoteAddr, err := ip.GetClientIP(i.ipParser, req)
	if err != nil {
		logger.Printf("Error obtaining real IP for trusted IP list: %v", err)
		// Possibly spoofed X-Real-IP header
		return false
	}

	if remoteAddr == nil {
		return false
	}

	return i.ips.Has(remoteAddr)
}
