package ip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEmptyNetSet(t *testing.T) {
	set := NewNetSet()

	ips := []string{
		"127.0.0.1",
		"241.163.75.163",
		"189.248.81.89",
		"167.75.10.139",
		"22.169.8.110",
		"::1",
		"114d:28ae:60a:7b12:b851:fd49:5ff9:9b9d",
		"4e73:55a5:6cd:29c7:5db6:673a:4608:1a3f",
		"f6b0:d7f3:8206:b529:ee3b:49ff:1b3b:9aac",
		"09d8:a74c:652f:3763:b87d:f068:b593:b588",
	}
	for _, ip := range ips {
		assert.Falsef(t, set.Has(net.ParseIP(ip)), "Empty NetSet must not have %q", ip)
	}
}

func TestV4ContainsEverything(t *testing.T) {
	set := NewNetSet()
	set.AddIPNet(net.IPNet{IP: net.ParseIP("0.0.0.0"), Mask: net.CIDRMask(0, 32)})

	ip4s := []string{
		"127.0.0.1",
		"250.169.183.192",
		"175.125.175.160",
		"178.244.137.158",
		"190.13.12.194",
	}
	for _, ip := range ip4s {
		assert.Truef(t, set.Has(net.ParseIP(ip)), "NetSet{\"0.0.0.0/0\"} must have %q", ip)
	}
	ip6s := []string{
		"::1",
		"7261:ca92:c9a5:4b79:2e:8889:b769:1d62",
		"f54f:10cb:e6a4:89f5:3366:1e3e:2d22:f68e",
		"d1f3:be6:60d:361:1717:4fe6:9812:1a6c",
		"7eaa:2a8:365c:b55f:67cd:96dd:602a:4385",
	}
	for _, ip := range ip6s {
		assert.Falsef(t, set.Has(net.ParseIP(ip)), "NetSet{\"0.0.0.0/0\"} must not have %q", ip)
	}
}

func TestV6ContainsEverything(t *testing.T) {
	set := NewNetSet()
	set.AddIPNet(net.IPNet{IP: net.ParseIP("::"), Mask: net.CIDRMask(0, 128)})

	ip4s := []string{
		"127.0.0.1",
		"216.163.140.97",
		"175.55.31.226",
		"115.112.186.19",
		"250.83.241.122",
	}
	for _, ip := range ip4s {
		assert.Falsef(t, set.Has(net.ParseIP(ip)), "NetSet{\"::/0\"} must not have %q", ip)
	}
	ip6s := []string{
		"::1",
		"fa3b:7f17:7521:d9f4:d855:51f9:4b63:de7f",
		"4d47:c29:2479:41ce:69f9:3d33:306a:91c8",
		"fe99:f364:f8cd:7a11:838:a36f:b9a1:965",
		"fb9e:d809:881d:9cee:533d:1ba5:592e:ea9b",
	}
	for _, ip := range ip6s {
		assert.Truef(t, set.Has(net.ParseIP(ip)), "NetSet{\"::/0\"} must have %q", ip)
	}
}

func TestLocalhostOnly(t *testing.T) {
	set := NewNetSet()
	set.AddIPNet(net.IPNet{IP: net.ParseIP("127.0.0.0"), Mask: net.CIDRMask(8, 32)})
	set.AddIPNet(net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)})

	included := []string{
		"127.0.0.1",
		"127.196.199.162",
		"127.78.85.40",
		"127.205.171.240",
		"127.121.187.93",
		"127.5.217.10",
		"127.22.172.251",
		"127.12.60.198",
		"127.110.240.252",
		"::1",
	}
	for _, ip := range included {
		assert.Truef(t, set.Has(net.ParseIP(ip)), "NetSet{\"127.0.0.0/8\", \"::1\"} must have %q", ip)
	}
	excluded := []string{
		"15.65.169.230",
		"196.72.207.65",
		"43.46.246.121",
		"69.147.193.224",
		"43.130.74.115",
		"8375:b8f9:70bf:a247:f55e:b0c0:c24f:eebe",
		"d325:aabf:ef49:2d46:ba47:1aa5:9e57:b0bf",
		"d2f6:831:170:e04e:bd6d:7ae7:e14a:71c3",
		"ca80:483f:bb7f:df2a:bceb:de5e:6129:9625",
		"f3fe:f771:9138:5d63:8e83:7033:2e6f:4762",
	}
	for _, ip := range excluded {
		assert.Falsef(t, set.Has(net.ParseIP(ip)), "NetSet{\"127.0.0.0/8\", \"::1\"} must not have %q", ip)
	}
}
