package main

import (
	"fmt"
	"net"
)

type ipCIDRSet struct {
	ip4NetMaps *[]*ipNetMap
	ip6NetMaps *[]*ipNetMap
}

func newIPCIDRSet(nets []*net.IPNet) *ipCIDRSet {
	ip4NetMaps := make([]*ipNetMap, 0)
	ip6NetMaps := make([]*ipNetMap, 0)

	w := &ipCIDRSet{
		ip4NetMaps: &ip4NetMaps,
		ip6NetMaps: &ip6NetMaps,
	}

	for _, net := range nets {
		w.addIP(net.IP, net.Mask)
	}

	return w
}

func (w ipCIDRSet) getNetMaps(ip net.IP) (netMaps *[]*ipNetMap) {
	// nolint:gocritic
	if ip.To4() != nil {
		netMaps = w.ip4NetMaps
	} else if ip.To16() != nil {
		netMaps = w.ip6NetMaps
	} else {
		panic(fmt.Sprintf("IP (%s) is neither 4-byte nor 16-byte?", ip.String()))
	}

	return netMaps
}

func (w ipCIDRSet) has(ip net.IP) bool {
	netMaps := w.getNetMaps(ip)
	for _, netMap := range *netMaps {
		if netMap.has(ip) {
			return true
		}
	}
	return false
}

func (w *ipCIDRSet) addIP(ip net.IP, mask net.IPMask) {
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
