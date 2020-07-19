package authorization

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

var result AuthorizationPolicy

func benchmarkRuleSetMatches(ruleCount int, b *testing.B) {
	rule1 := options.AuthorizationRule{
		Policy: options.AllowPolicy,
		Path:   "/[a-z]*/[a-z]*/[a-z]*",
		Methods: []string{
			"get",
			"put",
			"post",
			"patch",
			"head",
			"options",
		},
		IPs: []string{
			"10.0.0.0/24",
			"10.1.0.0/24",
			"10.2.1.0/24",
			"10.2.2.0/24",
			"10.3.3.0/24",
			"192.168.1.0/24",
			"192.168.2.0/24",
			"192.168.3.0/24",
			"192.168.0.128/25",
			"192.168.0.64/26",
			"192.168.0.32/27",
			"192.168.0.16/28",
		},
	}

	requestRules := options.RequestRules{}
	for i := 0; i <= ruleCount; i++ {
		requestRules = append(requestRules, rule1)
	}

	ruleSet, err := NewRuleSet(requestRules, func(_ *http.Request) net.IP {
		return net.IPv4(192, 168, 0, 1)
	})
	if err != nil {
		b.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/foo/bar/baz", nil)

	var r AuthorizationPolicy
	for n := 0; n < b.N; n++ {
		r = ruleSet.Matches(req)
		if r != NonePolicy {
			b.Fatal("expected policy not to match")
		}
	}
	// always store the result to a package level variable
	// so the compiler cannot eliminate the Benchmark itself.
	result = r
}

func BenchmarkRuleSetMatches1(b *testing.B)    { benchmarkRuleSetMatches(1, b) }
func BenchmarkRuleSetMatches10(b *testing.B)   { benchmarkRuleSetMatches(10, b) }
func BenchmarkRuleSetMatches25(b *testing.B)   { benchmarkRuleSetMatches(25, b) }
func BenchmarkRuleSetMatches50(b *testing.B)   { benchmarkRuleSetMatches(50, b) }
func BenchmarkRuleSetMatches100(b *testing.B)  { benchmarkRuleSetMatches(100, b) }
func BenchmarkRuleSetMatches250(b *testing.B)  { benchmarkRuleSetMatches(250, b) }
func BenchmarkRuleSetMatches500(b *testing.B)  { benchmarkRuleSetMatches(500, b) }
func BenchmarkRuleSetMatches1000(b *testing.B) { benchmarkRuleSetMatches(1000, b) }
