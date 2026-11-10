package sing_tun

import (
	"sync/atomic"

	tun "github.com/metacubex/sing-tun"
	E "github.com/metacubex/sing/common/exceptions"
)

// GoStackOptions is what a go stack implementation is handed. It carries the
// same fields sing-tun's own stacks get, plus the core's concrete handler:
// tun.Handler decides where a connection goes, but the handler's own type
// also carries the addresses the core resolved for the tunnel, which an
// implementation needs and the interface does not expose.
type GoStackOptions struct {
	tun.StackOptions

	// ListenerHandler is the handler the tunnel runs with.
	ListenerHandler *ListenerHandler
}

// GoStackFactory builds a go stack.
//
// The kernel does not carry a go stack itself. A build that has one
// registers it at start-up with SetGoStackFactory, and a build that does not
// refuses the stack instead of quietly running a different one: a
// configuration that asks for the go stack must either get it or fail.
type GoStackFactory func(options GoStackOptions) (tun.Stack, error)

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
func newGoStack(options GoStackOptions) (tun.Stack, error) {
	factory := goStackFactory.Load()
	if factory == nil {
		return nil, E.New("the go stack is not available in this build")
	}
	return (*factory)(options)
}
