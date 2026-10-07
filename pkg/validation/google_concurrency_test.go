package validation

import (
	"fmt"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
	"github.com/stretchr/testify/assert"
)

func TestValidateGoogleGroupMembershipConcurrency(t *testing.T) {
	for _, n := range []int{-1, 0, 1, 5, 10, 11} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			provider := options.Provider{GoogleConfig: options.GoogleOptions{GroupMembershipConcurrency: ptr.To(n)}}
			errors := validateGoogleConfig(provider)
			if n < 1 || n > 10 {
				assert.NotEmpty(t, errors)
			} else {
				assert.Empty(t, errors)
			}
		})
	}
	assert.Empty(t, validateGoogleConfig(options.Provider{}))
}
