package main

import (
	"fmt"
	"net"
)

type IPWhitelist struct {
	ip4Whitelist *[]*ipNetMap
	ip6Whitelist *[]*ipNetMap
}

func NewIPWhitelist(nets []*net.IPNet) *IPWhitelist {
	ip4Whitelist := make([]*ipNetMap, 0)
	ip6Whitelist := make([]*ipNetMap, 0)

	w := &IPWhitelist{
		ip4Whitelist: &ip4Whitelist,
		ip6Whitelist: &ip6Whitelist,
	}

	for _, net := range nets {
		w.addIP(net.IP, net.Mask)
	}

	return w
}

func (w IPWhitelist) getNetMaps(ip net.IP) (netMaps *[]*ipNetMap) {
	// nolint:gocritic
	if ip.To4() != nil {
		netMaps = w.ip4Whitelist
	} else if ip.To16() != nil {
		netMaps = w.ip6Whitelist
	} else {
		panic(fmt.Sprintf("IP (%s) is neither 4-byte nor 16-byte?", ip.String()))
	}

	return netMaps
}

func (w IPWhitelist) has(ip net.IP) bool {
	netMaps := w.getNetMaps(ip)
	for _, netMap := range *netMaps {
		if netMap.has(ip) {
			return true
		}
	}
	return false
}

func (w *IPWhitelist) addIP(ip net.IP, mask net.IPMask) {
	netMaps := w.getNetMaps(ip)

	ones, _ := mask.Size()
	var netMap *ipNetMap
	for i := 0; len(*netMaps) > i; i++ {
		if netMapOnes, _ := (*netMaps)[i].mask.Size(); netMapOnes == ones {
			netMap = (*netMaps)[i]
			break
		}
	}
	if netMap == nil {
		netMap = &ipNetMap{
			mask: mask,
			ips:  make(map[string]bool),
		}
		*netMaps = append(*netMaps, netMap)
	}

	netMap.ips[ip.String()] = true
}

type ipNetMap struct {
	mask net.IPMask
	ips  map[string]bool
}

func (m ipNetMap) has(ip net.IP) bool {
	ipMasked := ip.Mask(m.mask)
	if ipMasked == nil {
		panic(fmt.Sprintf(
			"Mismatch in net.IPMask and net.IP protocol version, cannot apply mask %s to %s",
			m.mask.String(), ip.String()))
	}

	if _, ok := m.ips[ipMasked.String()]; ok {
		return true
	}
	return false
}
