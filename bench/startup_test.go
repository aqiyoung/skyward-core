// Package bench holds the measurements that decide what is worth changing.
//
// The app's core is mihomo, and every millisecond before the first frame is a
// millisecond the user watches a spinner. These benchmarks measure one stage at
// a time, so a change is judged against the stage it touches rather than against
// a stopwatch on a phone.
package bench

import (
	"fmt"
	"strings"
	"testing"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
)

// syntheticProfile builds a profile shaped like a real subscription: many
// outbounds, a handful of groups, and a rule list long enough that order matters.
//
// It is written in block style on purpose: that is the shape a subscription
// arrives in, and the shape this reader actually parses.
//
// No providers and no geo files: those need the network, and measuring them here
// would measure the network instead of the parser.
func syntheticProfile(proxies, groups, rules int) []byte {
	var b strings.Builder

	fmt.Fprintln(&b, "mode: rule")
	fmt.Fprintln(&b, "log-level: silent")

	fmt.Fprintln(&b, "proxies:")
	for i := 0; i < proxies; i++ {
		fmt.Fprintf(&b, "  - name: node-%03d\n", i)
		fmt.Fprintln(&b, "    type: ss")
		fmt.Fprintf(&b, "    server: 192.0.2.%d\n", i%254+1)
		fmt.Fprintf(&b, "    port: %d\n", 10000+i)
		fmt.Fprintln(&b, "    cipher: aes-256-gcm")
		fmt.Fprintf(&b, "    password: p%03d\n", i)
	}

	fmt.Fprintln(&b, "proxy-groups:")
	for g := 0; g < groups; g++ {
		fmt.Fprintf(&b, "  - name: group-%02d\n", g)
		fmt.Fprintln(&b, "    type: select")
		fmt.Fprintln(&b, "    proxies:")
		for i := 0; i < proxies && i < 20; i++ {
			fmt.Fprintf(&b, "      - node-%03d\n", i)
		}
	}

	fmt.Fprintln(&b, "rules:")
	for i := 0; i < rules; i++ {
		switch i % 4 {
		case 0:
			fmt.Fprintf(&b, "  - DOMAIN-SUFFIX,site%03d.example.com,group-00\n", i)
		case 1:
			fmt.Fprintf(&b, "  - DOMAIN,host%03d.example.net,DIRECT\n", i)
		case 2:
			fmt.Fprintf(&b, "  - DOMAIN-KEYWORD,ads%03d,REJECT\n", i)
		default:
			fmt.Fprintf(&b, "  - IP-CIDR,10.%d.0.0/16,DIRECT,no-resolve\n", i%250)
		}
	}
	fmt.Fprintln(&b, "  - MATCH,group-00")

	return []byte(b.String())
}

// BenchmarkParseProfile is the whole startup cost the app pays before mihomo
// starts any listener: read the YAML, build every outbound, compile every rule.
func BenchmarkParseProfile(b *testing.B) {
	C.SetHomeDir(b.TempDir())
	raw := syntheticProfile(200, 12, 600)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := executor.ParseWithBytes(raw); err != nil {
			b.Fatalf("parse: %v", err)
		}
	}
}

// BenchmarkParseSmallProfile is the same for a profile of an ordinary size, so a
// change can be judged on both ends of the range.
func BenchmarkParseSmallProfile(b *testing.B) {
	C.SetHomeDir(b.TempDir())
	raw := syntheticProfile(10, 2, 40)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := executor.ParseWithBytes(raw); err != nil {
			b.Fatalf("parse: %v", err)
		}
	}
}
