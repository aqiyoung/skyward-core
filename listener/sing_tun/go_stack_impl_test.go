//go:build with_go_stack

package sing_tun

import (
	"net/netip"
	"syscall"
	"testing"

	gotun "github.com/sagernet/sing-tun"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/ranges"
	"github.com/stretchr/testify/assert"
)

func TestGoStackDeviceOptionsCarryTheTunnel(t *testing.T) {
	options := GoStackOptions{
		DeviceOptions: tun.Options{
			Name:         "Skyward",
			MTU:          1500,
			GSO:          true,
			AutoRoute:    true,
			DNSMode:      "fake-ip",
			DNSServers:   []netip.Addr{netip.MustParseAddr("1.1.1.1")},
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
			IncludeUID:   []ranges.Range[uint32]{{Start: 1000, End: 1999}},
		},
	}
	translated := goStackDeviceOptions(options)

	assert.Equal(t, "Skyward", translated.Name)
	assert.Equal(t, uint32(1500), translated.MTU)
	assert.True(t, translated.GSO)
	assert.True(t, translated.AutoRoute)
	assert.Equal(t, "fake-ip", translated.DNSMode)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, translated.DNSAddress)
	assert.Equal(t, options.DeviceOptions.Inet4Address, translated.Inet4Address)
	assert.Len(t, translated.IncludeUID, 1)
	assert.Equal(t, uint32(1000), translated.IncludeUID[0].Start)
	assert.Equal(t, uint32(1999), translated.IncludeUID[0].End)
}

func TestGoStackDeviceOptionsKnowWhoConfiguredTheDevice(t *testing.T) {
	// A descriptor that came from outside is already configured: the system
	// set its addresses and its routes before the tunnel started.
	external := goStackDeviceOptions(GoStackOptions{DeviceOptions: tun.Options{FileDescriptor: 7}})
	assert.True(t, external.EXP_ExternalConfiguration)

	// A device the stack opens itself is the stack's to configure.
	own := goStackDeviceOptions(GoStackOptions{DeviceOptions: tun.Options{}})
	assert.False(t, own.EXP_ExternalConfiguration)
}

func TestGoStackCongestionNames(t *testing.T) {
	assert.Equal(t, "bbr", goStackCongestion("bbr3"))
	assert.Equal(t, "bbr", goStackCongestion("bbr"))
	assert.Equal(t, "cubic", goStackCongestion("cubic"))
}

func TestGoStackJudgeFlowTakesTheDnsOver(t *testing.T) {
	handler := &ListenerHandler{
		DnsAddrPorts: []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53")},
	}
	stackHandler := goStackHandler{handler: handler}

	source := netip.MustParseAddrPort("10.0.0.2:5353")

	hijacked := stackHandler.JudgeFlow(uint8(syscall.IPPROTO_UDP), source, netip.MustParseAddrPort("1.1.1.1:53"), nil)
	assert.Equal(t, gotun.ActionHijackDNS, hijacked.Action)

	// Another name server is not the tunnel's business.
	other := stackHandler.JudgeFlow(uint8(syscall.IPPROTO_UDP), source, netip.MustParseAddrPort("8.8.8.8:53"), nil)
	assert.Equal(t, gotun.ActionAccept, other.Action)

	// A connection is never a DNS query, even to the same address.
	connection := stackHandler.JudgeFlow(uint8(syscall.IPPROTO_TCP), netip.MustParseAddrPort("10.0.0.2:5000"), netip.MustParseAddrPort("1.1.1.1:53"), nil)
	assert.Equal(t, gotun.ActionAccept, connection.Action)
}
