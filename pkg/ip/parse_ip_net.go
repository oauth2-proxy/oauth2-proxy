package ip

import (
	"fmt"
	"net"
	"strings"
)

func ParseIPNet(s string) *net.IPNet {
	if !strings.ContainsRune(s, '/') {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil
		}

		var mask net.IPMask
		switch {
		case ip.To4() != nil:
			mask = net.CIDRMask(32, 32)
		case ip.To16() != nil:
			mask = net.CIDRMask(128, 128)
		default:
			return nil
		}

		return &net.IPNet{
			IP:   ip,
			Mask: mask,
		}
	}

	switch ip, ipNet, err := net.ParseCIDR(s); {
	case err != nil:
		return nil
	case !ipNet.IP.Equal(ip):
		return nil
	default:
		return ipNet
	}
}

func ParseNetSet(ipStrs []string) (*NetSet, error) {
	netSet := NewNetSet()

	for _, ipStr := range ipStrs {
		ipNet := ParseIPNet(ipStr)
		if ipNet == nil {
			return nil, fmt.Errorf("could not parse IP network (%s)", ipStr)
		}

		netSet.AddIPNet(*ipNet)
	}

	return netSet, nil
}
