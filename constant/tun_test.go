package constant

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTunStackNames(t *testing.T) {
	for name, expected := range map[string]TUNStack{
		"gvisor": TunGvisor,
		"system": TunSystem,
		"mixed":  TunMixed,
		"mips":   TunMips,
		"go":     TunGo,
	} {
		var stack TUNStack
		assert.NoError(t, stack.UnmarshalText([]byte(name)))
		assert.Equal(t, expected, stack)
	}
}

func TestTunStackRejectsAnUnknownName(t *testing.T) {
	var stack TUNStack
	assert.Error(t, stack.UnmarshalText([]byte("go2")))
}

// The stack numbers travel through the API and through saved profiles, so the
// order the stacks were declared in must not move.
func TestTunStackNumbersAreStable(t *testing.T) {
	assert.Equal(t, TunGvisor, TUNStack(0))
	assert.Equal(t, TunSystem, TUNStack(1))
	assert.Equal(t, TunMixed, TUNStack(2))
	assert.Equal(t, TunMips, TUNStack(3))
	assert.Equal(t, TunGo, TUNStack(4))
}
