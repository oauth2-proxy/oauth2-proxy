package ip

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseIPNet(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedIP   net.IP
		expectedMask net.IPMask
	}{
		{
			name:         "ipv4 address",
			input:        "127.0.0.1",
			expectedIP:   net.ParseIP("127.0.0.1"),
			expectedMask: net.CIDRMask(32, 32),
		},
		{
			name:         "ipv6 address",
			input:        "::1",
			expectedIP:   net.ParseIP("::1"),
			expectedMask: net.CIDRMask(128, 128),
		},
		{
			name:         "ipv4 cidr",
			input:        "10.0.0.0/24",
			expectedIP:   net.ParseIP("10.0.0.0"),
			expectedMask: net.CIDRMask(24, 32),
		},
		{
			name:         "ipv6 cidr",
			input:        "2001:db8::/64",
			expectedIP:   net.ParseIP("2001:db8::"),
			expectedMask: net.CIDRMask(64, 128),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ipNet := ParseIPNet(test.input)

			assert.NotNil(t, ipNet)
			if ipNet == nil {
				return
			}

			assert.True(t, test.expectedIP.Equal(ipNet.IP))
			assert.Equal(t, test.expectedMask, ipNet.Mask)
		})
	}
}

func TestParseIPNetRejectsInvalidNetworks(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "invalid ip",
			input: "not-an-ip",
		},
		{
			name:  "ipv4 cidr with host bits set",
			input: "10.0.0.1/24",
		},
		{
			name:  "ipv6 cidr with host bits set",
			input: "2001:db8::1/64",
		},
		{
			name:  "invalid cidr mask",
			input: "10.0.0.0/33",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Nil(t, ParseIPNet(test.input))
		})
	}
}

func TestParseNetSet(t *testing.T) {
	netSet, err := ParseNetSet([]string{
		"127.0.0.1",
		"10.0.0.0/24",
		"::1",
		"2001:db8::/64",
	})

	assert.NoError(t, err)
	assert.NotNil(t, netSet)
	if netSet == nil {
		return
	}

	assert.True(t, netSet.Has(net.ParseIP("127.0.0.1")))
	assert.True(t, netSet.Has(net.ParseIP("10.0.0.55")))
	assert.True(t, netSet.Has(net.ParseIP("::1")))
	assert.True(t, netSet.Has(net.ParseIP("2001:db8::abcd")))

	assert.False(t, netSet.Has(net.ParseIP("127.0.0.2")))
	assert.False(t, netSet.Has(net.ParseIP("10.0.1.1")))
	assert.False(t, netSet.Has(net.ParseIP("::2")))
	assert.False(t, netSet.Has(net.ParseIP("2001:db9::1")))
}

func TestParseNetSetReturnsErrorForInvalidNetwork(t *testing.T) {
	netSet, err := ParseNetSet([]string{"127.0.0.1", "10.0.0.1/24"})

	assert.Nil(t, netSet)
	assert.EqualError(t, err, "could not parse IP network (10.0.0.1/24)")
}
