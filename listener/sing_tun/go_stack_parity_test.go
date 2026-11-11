//go:build with_go_stack

package sing_tun

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"

	gotun "github.com/sagernet/sing-tun"
	goM "github.com/sagernet/sing/common/metadata"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/stretchr/testify/assert"
)

// parityObserver is one stack's view of the traffic it hands to the core.
//
// The P2 gate compares this shape between the legacy stack and the go stack:
// connection count, rule hits, DNS answers, fake-ip mappings and UDP sessions
// all have to line up. Only the go side is wired today. The legacy side
// arrives with the end-to-end harness; until then these tables pin the pure
// conversions that harness will rely on, so a mismatch cannot be blamed on
// an address that changed shape on its way across the two sing forks.
type parityObserver struct {
	mu          sync.Mutex
	connections []M.Metadata
	packets     []M.Metadata
	dnsHijack   bool
}

func (o *parityObserver) ShouldHijackDns(netip.AddrPort) bool { return o.dnsHijack }

func (o *parityObserver) NewConnection(_ context.Context, conn net.Conn, metadata M.Metadata) error {
	o.mu.Lock()
	o.connections = append(o.connections, metadata)
	o.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	return nil
}

func (o *parityObserver) NewPacketConnection(_ context.Context, _ N.PacketConn, metadata M.Metadata) error {
	o.mu.Lock()
	o.packets = append(o.packets, metadata)
	o.mu.Unlock()
	return nil
}

// Every shape an address can take has to survive the sagernet <-> metacubex
// crossing unchanged. A domain, an IPv4 address and an IPv6 address are three
// different states on both sides, and the port must not be lost for any of
// them. The end-to-end parity comparison reads exactly these fields.
func TestGoStackMetadataCarriesEveryAddressShape(t *testing.T) {
	cases := []struct {
		name string
		addr goM.Socksaddr
	}{
		{"ipv4", goM.Socksaddr{Addr: netip.MustParseAddr("10.0.0.2"), Port: 40000}},
		{"ipv6", goM.Socksaddr{Addr: netip.MustParseAddr("2001:db8::1"), Port: 8443}},
		{"domain", goM.Socksaddr{Fqdn: "example.com", Port: 443}},
		{"domain without a port", goM.Socksaddr{Fqdn: "example.com"}},
		{"zero", goM.Socksaddr{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mine := fromGoSocksaddr(tc.addr)
			assert.Equal(t, tc.addr.Addr, mine.Addr)
			assert.Equal(t, tc.addr.Port, mine.Port)
			assert.Equal(t, tc.addr.Fqdn, mine.Fqdn)

			back := toGoSocksaddr(mine)
			assert.Equal(t, tc.addr.Addr, back.Addr)
			assert.Equal(t, tc.addr.Port, back.Port)
			assert.Equal(t, tc.addr.Fqdn, back.Fqdn)
		})
	}
}

// The stack may only take a query over when the core's handler claims it.
// Anything else -- a TCP flow, another name server, a handler that declines,
// or no handler at all -- stays on the ordinary path. A wrong hijack here
// would make the two stacks disagree about DNS before any rule is consulted.
func TestGoStackJudgeFlowFollowsTheHandlersDnsDecision(t *testing.T) {
	source := netip.MustParseAddrPort("10.0.0.2:5353")
	dns := netip.MustParseAddrPort("1.1.1.1:53")
	other := netip.MustParseAddrPort("8.8.8.8:53")
	udp := uint8(syscall.IPPROTO_UDP)
	tcp := uint8(syscall.IPPROTO_TCP)

	claims := goStackHandler{handler: &parityObserver{dnsHijack: true}}
	assert.Equal(t, gotun.ActionHijackDNS, claims.JudgeFlow(udp, source, dns, nil).Action)
	assert.Equal(t, gotun.ActionAccept, claims.JudgeFlow(tcp, source, dns, nil).Action)
	assert.Equal(t, gotun.ActionAccept, claims.JudgeFlow(udp, source, other, nil).Action)

	declines := goStackHandler{handler: &parityObserver{dnsHijack: false}}
	assert.Equal(t, gotun.ActionAccept, declines.JudgeFlow(udp, source, dns, nil).Action)

	assert.Equal(t, gotun.ActionAccept, (goStackHandler{}).JudgeFlow(udp, source, dns, nil).Action)
}
