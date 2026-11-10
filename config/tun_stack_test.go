package config

import (
	"testing"

	"github.com/metacubex/mihomo/common/yaml"
	C "github.com/metacubex/mihomo/constant"
	"github.com/stretchr/testify/assert"
)

func TestRawTunParsesTheGoStack(t *testing.T) {
	var raw RawTun
	assert.NoError(t, yaml.Unmarshal([]byte("stack: go\n"), &raw))
	assert.Equal(t, C.TunGo, raw.Stack)
}

func TestRawTunKeepsTheOtherStacks(t *testing.T) {
	for name, expected := range map[string]C.TUNStack{
		"gvisor": C.TunGvisor,
		"system": C.TunSystem,
		"mixed":  C.TunMixed,
		"mips":   C.TunMips,
	} {
		var raw RawTun
		assert.NoError(t, yaml.Unmarshal([]byte("stack: "+name+"\n"), &raw))
		assert.Equal(t, expected, raw.Stack)
	}
}

func TestRawTunRejectsAnUnknownStack(t *testing.T) {
	var raw RawTun
	assert.Error(t, yaml.Unmarshal([]byte("stack: go2\n"), &raw))
}
