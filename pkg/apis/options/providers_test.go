package options

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("OIDCOptions EnsureDefaults", func() {
	It("defaults LazyDiscovery to false when unset", func() {
		o := &OIDCOptions{}
		o.EnsureDefaults()

		Expect(o.LazyDiscovery).ToNot(BeNil())
		Expect(*o.LazyDiscovery).To(Equal(DefaultOIDCLazyDiscovery))
	})
})
