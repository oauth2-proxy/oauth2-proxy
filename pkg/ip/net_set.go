package ip

import (
	"fmt"
	"net"
)

// Fast lookup table for intersection of a single IP address within a collection of CIDR networks.
//
// Supports 4-byte (IPv4) and 16-byte (IPv6) networks.
//
// Provides O(1) best-case, O(log(n)) worst-case performance.
// In practice netmasks included will generally only be of standard lengths:
// - /8, /16, /24, and /32 for IPv4
// - /64 and /128 for IPv6.
// As a result, typical lookup times will lean closer to best-case rather than worst-case even when most of the internet
// is included.
type NetSet struct {
	ip4NetMaps []ipNetMap
	ip6NetMaps []ipNetMap
}

// Create a new NetSet with all of the provided networks.
func NewNetSet() *NetSet {
	return &NetSet{
		ip4NetMaps: make([]ipNetMap, 0),
		ip6NetMaps: make([]ipNetMap, 0),
	}
}

// Check if `ip` is in the set, true if within the set otherwise false.
func (w *NetSet) Has(ip net.IP) bool {
	netMaps := w.getNetMaps(ip)

	// Check all ipNetMaps for intersection with `ip`.
	for _, netMap := range *netMaps {
		if netMap.has(ip) {
			return true
		}
	}
	return false
}

// Add an CIDR network to the set.
func (w *NetSet) AddIPNet(ipNet net.IPNet) {
	netMaps := w.getNetMaps(ipNet.IP)

	// Determine the size / number of ones in the CIDR network mask.
	ones, _ := ipNet.Mask.Size()

	var netMap *ipNetMap

	// Search for the ipNetMap containing networks with the same number of ones.
	for i := 0; len(*netMaps) > i; i++ {
		if netMapOnes, _ := (*netMaps)[i].mask.Size(); netMapOnes == ones {
			netMap = &(*netMaps)[i]
			break
		}
	}

	// Create a new ipNetMap if none with this number of ones have been created yet.
	if netMap == nil {
		netMap = &ipNetMap{
			mask: ipNet.Mask,
			ips:  make(map[string]bool),
		}
		*netMaps = append(*netMaps, *netMap)
		// Recurse once now that there exists an netMap.
		w.AddIPNet(ipNet)
		return
	}

	// Add the IP to the ipNetMap.
	netMap.ips[ipNet.IP.String()] = true
}

// Get the appropriate array of networks for the given IP version.
func (w *NetSet) getNetMaps(ip net.IP) (netMaps *[]ipNetMap) {
	switch {
	case ip.To4() != nil:
		netMaps = &w.ip4NetMaps
	case ip.To16() != nil:
		netMaps = &w.ip6NetMaps
	default:
		panic(fmt.Sprintf("IP (%s) is neither 4-byte nor 16-byte?", ip.String()))
	}

	return netMaps
}

// Hash-set of CIDR networks with the same mask size.
type ipNetMap struct {
	mask net.IPMask
	ips  map[string]bool
}

// Check if the IP is in any of the CIDR networks contained in this map.
func (m ipNetMap) has(ip net.IP) bool {
	// Apply the mask to the IP to remove any irrelevant bits in the IP.
	ipMasked := ip.Mask(m.mask)
	if ipMasked == nil {
		panic(fmt.Sprintf(
			"Mismatch in net.IPMask and net.IP protocol version, cannot apply mask %s to %s",
			m.mask.String(), ip.String()))
	}

	// Check if the masked IP is the same as any of the networks.
	if _, ok := m.ips[ipMasked.String()]; ok {
		return true
	}
	return false
}
