package main

import (
	"fmt"
	"net"
)

type IPWhitelist struct {
	ip4Whitelist []*ip4NetMap
	ip6Whitelist []*ip16NetMap
}

func NewIPWhitelist(nets []*net.IPNet) *IPWhitelist {
	var w IPWhitelist

	for _, net := range nets {
		if ip4 := net.IP.To4(); ip4 != nil {
			var netMap *ip4NetMap
			if netMap = w.getIP4NetMap(net.Mask); netMap == nil {
				netMap = &ip4NetMap{
					mask: net.Mask,
					ips:  map[[4]byte]bool{},
				}
				w.ip4Whitelist = append(w.ip4Whitelist, netMap)
			}

			var ip4AsBytes [4]byte
			copy(ip4AsBytes[:], ip4)
			netMap.ips[ip4AsBytes] = true
		} else if ip16 := net.IP.To16(); ip16 != nil {
			var netMap *ip16NetMap
			if netMap = w.getIP6NetMap(net.Mask); netMap == nil {
				netMap = &ip16NetMap{
					mask: net.Mask,
					ips:  map[[16]byte]bool{},
				}
				w.ip6Whitelist = append(w.ip6Whitelist, netMap)
			}

			var ip16AsBytes [16]byte
			copy(ip16AsBytes[:], ip16)
			netMap.ips[ip16AsBytes] = true
		} else {
			panic(fmt.Sprintf("IPNet (%s) is neither 4-byte or 16-byte?", net.String()))
		}
	}

	return &w
}

func (w IPWhitelist) has(ip net.IP) bool {
	if ip.To4() != nil {
		for _, ipNetMap := range w.ip4Whitelist {
			if ipNetMap.has(ip) {
				return true
			}
		}
	} else if ip.To16() != nil {
		for _, ipNetMap := range w.ip6Whitelist {
			if ipNetMap.has(ip) {
				return true
			}
		}
	} else {
		panic(fmt.Sprintf("IP (%s) is neither 4-byte nor 16-byte?", ip.String()))
	}
	return false
}

func (w IPWhitelist) getIP4NetMap(mask net.IPMask) *ip4NetMap {
	ones, _ := mask.Size()
	for _, netMap := range w.ip4Whitelist {
		if netMapOnes, _ := netMap.mask.Size(); netMapOnes == ones {
			return netMap
		}
	}

	return nil
}

func (w IPWhitelist) getIP6NetMap(mask net.IPMask) *ip16NetMap {
	ones, _ := mask.Size()
	for _, netMap := range w.ip6Whitelist {
		if netMapOnes, _ := netMap.mask.Size(); netMapOnes == ones {
			return netMap
		}
	}

	return nil
}

type ip4NetMap struct {
	mask net.IPMask
	ips  map[[4]byte]bool
}

func (m ip4NetMap) has(ip net.IP) bool {
	ipMasked := ip.Mask(m.mask)
	if ipMasked == nil {
		panic(fmt.Sprintf("Attempt to mask non-4-byte IP (%s) as 4-byte IP", ip.String()))
	}
	ip4 := ipMasked.To4()
	var ip4AsBytes [4]byte
	copy(ip4AsBytes[:], ip4)

	if _, ok := m.ips[ip4AsBytes]; ok {
		return true
	}
	return false
}

type ip16NetMap struct {
	mask net.IPMask
	ips  map[[16]byte]bool
}

func (m ip16NetMap) has(ip net.IP) bool {
	ipMasked := ip.Mask(m.mask)
	if ipMasked == nil {
		panic(fmt.Sprintf("Attempt to mask non-16-byte IP (%s) as 16-byte IP", ip.String()))
	}
	ip16 := ipMasked.To16()
	var ip16AsBytes [16]byte
	copy(ip16AsBytes[:], ip16)

	if _, ok := m.ips[ip16AsBytes]; ok {
		return true
	}
	return false
}
