//go:build with_go_stack

package sing_tun

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
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
	mu          sync.Mutex
	packets     []M.Metadata
	connections []M.Metadata
}

func (h *recordingGoStackHandler) ShouldHijackDns(targetAddr netip.AddrPort) bool {
	return false
}

func (h *recordingGoStackHandler) NewConnection(
	ctx context.Context,
	conn net.Conn,
	metadata M.Metadata,
) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.connections = append(h.connections, metadata)
	return nil
}

func (h *recordingGoStackHandler) recordedConnections() []M.Metadata {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]M.Metadata(nil), h.connections...)
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
	// A datagram socket pair: one end is the descriptor the stack reads
	// from, the other is where the system writes.
	socketPath := filepath.Join(t.TempDir(), "tun.sock")
	listener, err := net.ListenPacket("unixgram", socketPath)
	assert.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	system, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socketPath, Net: "unixgram"})
	assert.NoError(t, err)
	t.Cleanup(func() { _ = system.Close() })

	descriptor, err := listener.(*net.UnixConn).File()
	assert.NoError(t, err)
	core := int(descriptor.Fd())

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
	_, err = system.Write(packet)
	assert.NoError(t, err)

	assert.Eventually(t, func() bool {
		return len(handler.recorded()) == 1
	}, 10*time.Second, 20*time.Millisecond)

	recorded := handler.recorded()[0]
	assert.Equal(t, netip.MustParseAddrPort("172.19.0.2:40001"), recorded.Source.AddrPort())
}

// tcpSegment builds a TCP segment the way the kernel hands one to the
// tunnel: an IPv4 header, a TCP header and the payload.
func tcpSegment(source, destination netip.Addr, sequence, acknowledgment uint32, flags byte, payload []byte) []byte {
	sourceAddress := source.As4()
	destinationAddress := destination.As4()
	segmentLength := 20 + len(payload)

	packet := make([]byte, 20+segmentLength)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(20+segmentLength))
	packet[8] = 64
	packet[9] = 6 // TCP
	copy(packet[12:16], sourceAddress[:])
	copy(packet[16:20], destinationAddress[:])

	binary.BigEndian.PutUint32(packet[20:24], sequence)
	binary.BigEndian.PutUint32(packet[24:28], acknowledgment)
	packet[28] = 0x50 // five words of header, no options
	packet[29] = flags
	binary.BigEndian.PutUint16(packet[30:32], 65535)
	copy(packet[40:], payload)

	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[0:20]))
	binary.BigEndian.PutUint16(packet[32:34], tcpChecksum(sourceAddress, destinationAddress, packet[20:40+len(payload)]))
	return packet
}

// tcpChecksum is the checksum of a segment: the pseudo header the route
// would carry, and the segment itself.
func tcpChecksum(source, destination [4]byte, segment []byte) uint16 {
	pseudo := make([]byte, 12+len(segment))
	copy(pseudo[0:4], source[:])
	copy(pseudo[4:8], destination[:])
	pseudo[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(segment)))
	copy(pseudo[12:], segment)
	return internetChecksum(pseudo)
}

// The stack waits for the handshake to finish before it hands a connection
// over: the handler has to be able to take the connection as it is.
func TestGoStackFinishesTheHandshakeBeforeItHandsOver(t *testing.T) {
	handler := &recordingGoStackHandler{}
	outbound := make(chan []byte, 8)
	device := gotun.NewMemoryTun(gotun.MemoryTunOptions{
		MTU: 1500,
		Outbound: func(packets []*gobuf.Buffer) {
			for _, packet := range packets {
				outbound <- append([]byte(nil), packet.Bytes()...)
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
			Name:         "go-stack-handshake",
			MTU:          1500,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		},
		Handler:    handler,
		UDPTimeout: time.Second * 30,
	})
	assert.NoError(t, err)
	assert.NoError(t, stack.Start())
	t.Cleanup(func() { _ = stack.Close() })

	const clientSequence = uint32(1000)
	source := netip.MustParseAddrPort("172.19.0.2:40000")
	destination := netip.MustParseAddrPort("172.19.0.1:80")

	// The handshake starts.
	syn := tcpSegment(source.Addr(), destination.Addr(), clientSequence, 0, 0x02, nil)
	assert.NoError(t, device.WaitWritePackets([][]byte{syn}))

	// The stack answers with a sequence number of its own.
	var answer []byte
	select {
	case answer = <-outbound:
	case <-time.After(10 * time.Second):
		t.Fatal("the stack did not answer the handshake")
	}
	serverSequence := binary.BigEndian.Uint32(answer[20:24])
	assert.Equal(t, clientSequence+1, binary.BigEndian.Uint32(answer[24:28]))

	// The handshake finishes.
	ack := tcpSegment(source.Addr(), destination.Addr(), clientSequence+1, serverSequence+1, 0x10, nil)
	assert.NoError(t, device.WaitWritePackets([][]byte{ack}))

	// Only now does the connection reach the handler.
	assert.Eventually(t, func() bool {
		return len(handler.recordedConnections()) == 1
	}, 10*time.Second, 20*time.Millisecond)

	recorded := handler.recordedConnections()[0]
	assert.Equal(t, source, recorded.Source.AddrPort())
	assert.Equal(t, destination, recorded.Destination.AddrPort())
}
