//go:build with_go_stack

package sing_tun

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	gotun "github.com/sagernet/sing-tun"
	gobuf "github.com/sagernet/sing/common/buf"

	tun "github.com/metacubex/sing-tun"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/stretchr/testify/assert"
)

// recordingGoStackHandler remembers what the stack handed over.
type recordingGoStackHandler struct {
	mu      sync.Mutex
	packets []M.Metadata
}

func (h *recordingGoStackHandler) ShouldHijackDns(targetAddr netip.AddrPort) bool {
	return false
}

func (h *recordingGoStackHandler) NewConnection(
	ctx context.Context,
	conn net.Conn,
	metadata M.Metadata,
) error {
	return nil
}

func (h *recordingGoStackHandler) NewPacketConnection(
	ctx context.Context,
	conn N.PacketConn,
	metadata M.Metadata,
) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.packets = append(h.packets, metadata)
	return nil
}

func (h *recordingGoStackHandler) recorded() []M.Metadata {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]M.Metadata(nil), h.packets...)
}

// udpPacket builds a datagram the way the kernel hands one to the tunnel:
// an IPv4 header, a UDP header and the payload.
func udpPacket(source, destination netip.AddrPort, payload []byte) []byte {
	sourceAddress := source.Addr().As4()
	destinationAddress := destination.Addr().As4()
	udpLength := 8 + len(payload)

	packet := make([]byte, 20+udpLength)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(20+udpLength))
	packet[8] = 64
	packet[9] = 17 // UDP
	copy(packet[12:16], sourceAddress[:])
	copy(packet[16:20], destinationAddress[:])
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[0:20]))

	binary.BigEndian.PutUint16(packet[20:22], source.Port())
	binary.BigEndian.PutUint16(packet[22:24], destination.Port())
	binary.BigEndian.PutUint16(packet[24:26], uint16(udpLength))
	copy(packet[28:], payload)
	return packet
}

// internetChecksum is the internet checksum: the one's complement of the
// one's complement sum of the header, in 16 bit words.
func internetChecksum(data []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(data); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[index : index+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// The stack has to read a packet off the device and carry it to the core's
// handler. Everything else in the tunnel is the handler's business.
func TestGoStackCarriesAPacketToTheHandler(t *testing.T) {
	handler := &recordingGoStackHandler{}
	device := gotun.NewMemoryTun(gotun.MemoryTunOptions{
		MTU: 1500,
		Outbound: func(packets []*gobuf.Buffer) {
			for _, packet := range packets {
				packet.Release()
			}
		},
	})

	original := goStackDeviceFactory
	goStackDeviceFactory = func(options gotun.Options) (gotun.Tun, error) {
		return device, nil
	}
	t.Cleanup(func() { goStackDeviceFactory = original })

	stack, err := buildGoStack(GoStackOptions{
		Context: context.Background(),
		DeviceOptions: tun.Options{
			Name:         "go-stack-test",
			MTU:          1500,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		},
		Handler:    handler,
		UDPTimeout: time.Second * 30,
	})
	assert.NoError(t, err)
	assert.NoError(t, stack.Start())
	t.Cleanup(func() { _ = stack.Close() })

	// A datagram from the tunnel's own subnet to the tunnel's own address.
	packet := udpPacket(
		netip.MustParseAddrPort("172.19.0.2:40000"),
		netip.MustParseAddrPort("172.19.0.1:53"),
		[]byte("hello"),
	)
	assert.NoError(t, device.WaitWritePackets([][]byte{packet}))

	assert.Eventually(t, func() bool {
		return len(handler.recorded()) == 1
	}, 10*time.Second, 20*time.Millisecond)

	recorded := handler.recorded()[0]
	assert.Equal(t, netip.MustParseAddrPort("172.19.0.2:40000"), recorded.Source.AddrPort())
	assert.Equal(t, netip.MustParseAddrPort("172.19.0.1:53"), recorded.Destination.AddrPort())
}

// The device can also arrive as a descriptor, which is how the Android
// tunnel hands its device over: the system opens it, the core takes it.
func TestGoStackCarriesAPacketFromADescriptor(t *testing.T) {
	handler := &recordingGoStackHandler{}
	descriptors, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	assert.NoError(t, err)
	core, system := descriptors[0], descriptors[1]
	t.Cleanup(func() {
		_ = syscall.Close(core)
		_ = syscall.Close(system)
	})

	original := goStackDeviceFactory
	goStackDeviceFactory = func(options gotun.Options) (gotun.Tun, error) {
		options.FileDescriptor = core
		return gotun.New(options)
	}
	t.Cleanup(func() { goStackDeviceFactory = original })

	stack, err := buildGoStack(GoStackOptions{
		Context: context.Background(),
		DeviceOptions: tun.Options{
			Name:           "go-stack-descriptor",
			MTU:            1500,
			FileDescriptor: core,
			Inet4Address:   []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		},
		Handler:    handler,
		UDPTimeout: time.Second * 30,
	})
	assert.NoError(t, err)
	assert.NoError(t, stack.Start())
	t.Cleanup(func() { _ = stack.Close() })

	packet := udpPacket(
		netip.MustParseAddrPort("172.19.0.2:40001"),
		netip.MustParseAddrPort("172.19.0.1:53"),
		[]byte("hello"),
	)
	_, err = syscall.Write(system, packet)
	assert.NoError(t, err)

	assert.Eventually(t, func() bool {
		return len(handler.recorded()) == 1
	}, 10*time.Second, 20*time.Millisecond)

	recorded := handler.recorded()[0]
	assert.Equal(t, netip.MustParseAddrPort("172.19.0.2:40001"), recorded.Source.AddrPort())
}
