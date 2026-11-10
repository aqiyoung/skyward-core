package sing_tun

import (
	"context"
	"sync/atomic"
	"time"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/control"
	E "github.com/metacubex/sing/common/exceptions"
)

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

	// Handler decides where a connection goes. It is the core's handler, so
	// the routing stays where it always was: the stack only carries the
	// connection to it.
	Handler *ListenerHandler

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
