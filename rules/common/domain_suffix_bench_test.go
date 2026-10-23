package common

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func BenchmarkDomainSuffixMatch(b *testing.B) {
	rule := NewDomainSuffix("Example.COM", "proxy")
	md := &C.Metadata{Host: "a.b.example.com"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rule.Match(md, C.RuleMatchHelper{})
	}
}
