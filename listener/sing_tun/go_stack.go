package sing_tun

import (
	"context"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/control"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// GoStackHandler is what the go stack asks about the traffic it carries.
//
// The core's handler answers it. The stack only carries the traffic: where
// a connection goes is still the handler's business, so both stacks run on
// one set of rules.
type GoStackHandler interface {
	// ShouldHijackDns says whether the tunnel answers this query itself.
	ShouldHijackDns(targetAddr netip.AddrPort) bool

	// NewConnection takes a connection the stack opened.
	NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error

	// NewPacketConnection takes a packet connection the stack opened.
	NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error
}

// GoStackOptions is what a go stack implementation is handed.
//
// The kernel does not build the device for the go stack. The stack needs the
// file descriptor the device owns, and a stack that reads through an
// interface cannot hand it over, so the stack brings its own device and the
// options the tunnel is built from.
type GoStackOptions struct {
	Context context.Context

	// DeviceOptions are the tunnel's settings. The implementation turns them
	// into the options its own stack understands.
	DeviceOptions tun.Options

	// Handler decides where a connection goes.
	Handler GoStackHandler

	UDPTimeout        time.Duration
	ICMPTimeout       time.Duration
	CongestionControl string

	EndpointIndependentNat bool
	ForwarderBindInterface bool

	// InterfaceFinder finds the interface the tunnel's own traffic leaves
	// by. A nil finder leaves the choice to the stack.
	InterfaceFinder control.InterfaceFinder
}

// GoStack is a go stack together with the device it owns.
type GoStack interface {
	tun.Stack

	// Device is the tunnel device the stack reads and writes. Closing it is
	// the stack's work: the device belongs to the stack.
	Device() tun.Tun
}

// GoStackFactory builds a go stack.
//
// The kernel does not carry a go stack itself. A build that has one
// registers it at start-up with SetGoStackFactory, and a build that does not
// refuses the stack instead of quietly running another one: a configuration
// that asks for the go stack must either get it or fail.
type GoStackFactory func(options GoStackOptions) (GoStack, error)

var goStackFactory atomic.Pointer[GoStackFactory]

// SetGoStackFactory registers the go stack implementation. Passing nil
// removes it again, which is what a test does to get the refusal back.
func SetGoStackFactory(factory GoStackFactory) {
	if factory == nil {
		goStackFactory.Store(nil)
		return
	}
	goStackFactory.Store(&factory)
}

// newGoStack builds the go stack the configuration asked for.
func newGoStack(options GoStackOptions) (GoStack, error) {
	factory := goStackFactory.Load()
	if factory == nil {
		return nil, E.New("the go stack is not available in this build")
	}
	return (*factory)(options)
}
