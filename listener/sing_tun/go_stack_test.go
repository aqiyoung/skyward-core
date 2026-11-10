package sing_tun

import (
	"testing"

	tun "github.com/metacubex/sing-tun"
	"github.com/stretchr/testify/assert"
)

type fakeGoStack struct {
	started bool
}

func (f *fakeGoStack) Start() error {
	f.started = true
	return nil
}

func (f *fakeGoStack) Close() error {
	return nil
}

func (f *fakeGoStack) Device() tun.Tun {
	return nil
}

// A build without a go stack must say so. Running another stack in its place
// would leave the configuration describing something the tunnel is not doing.
func TestGoStackIsRefusedWithoutAnImplementation(t *testing.T) {
	SetGoStackFactory(nil)

	stack, err := newGoStack(GoStackOptions{})

	assert.Nil(t, stack)
	assert.ErrorContains(t, err, "not available")
}

func TestGoStackFactoryBuildsTheStack(t *testing.T) {
	t.Cleanup(func() { SetGoStackFactory(nil) })

	var seen GoStackOptions
	built := &fakeGoStack{}
	SetGoStackFactory(func(options GoStackOptions) (GoStack, error) {
		seen = options
		return built, nil
	})

	handler := &ListenerHandler{}
	stack, err := newGoStack(GoStackOptions{Handler: handler})

	assert.NoError(t, err)
	assert.Same(t, built, stack)
	assert.Same(t, handler, seen.Handler)
}

func TestGoStackFactoryErrorIsReported(t *testing.T) {
	t.Cleanup(func() { SetGoStackFactory(nil) })

	SetGoStackFactory(func(options GoStackOptions) (GoStack, error) {
		return nil, assert.AnError
	})

	stack, err := newGoStack(GoStackOptions{})

	assert.Nil(t, stack)
	assert.ErrorIs(t, err, assert.AnError)
}
