//go:build with_go_stack

package sing_tun

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gotun "github.com/sagernet/sing-tun"
	gobuf "github.com/sagernet/sing/common/buf"
)

// parityFlow is the part of M.Metadata the two stacks must agree on before
// any rule is consulted. Where a connection goes is the handler's business,
// and both stacks use the same handler; what can still diverge is the shape
// of the connection each stack hands over. The P2 gate compares these flows
// (plus DNS answers and fake-ip mappings once those harnesses exist).
type parityFlow struct {
	Network     string
	Source      netip.AddrPort
	Destination netip.AddrPort
}

func flowFrom(network string, m M.Metadata) parityFlow {
	return parityFlow{
		Network:     network,
		Source:      m.Source.AddrPort(),
		Destination: m.Destination.AddrPort(),
	}
}

type parityRecorder struct {
	mu    sync.Mutex
	flows []parityFlow
}

func (r *parityRecorder) add(f parityFlow) {
	r.mu.Lock()
	r.flows = append(r.flows, f)
	r.mu.Unlock()
}

func (r *parityRecorder) snapshot() []parityFlow {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]parityFlow(nil), r.flows...)
}

// parityTun is the legacy stack's in-memory device. metacubex/sing-tun has
// the same helper in its own tests, but it is package-private there, so this
// is a local copy of the io.ReadWriter + Close contract. The mips read loop
// takes the plain Read path for a device that is not a WinTun/LinuxTUN/
// DarwinTUN, which is exactly this shape.
type parityTun struct {
	in   chan []byte
	out  chan []byte
	done chan struct{}
	once sync.Once
}

func newParityTun() *parityTun {
	return &parityTun{
		in:   make(chan []byte, 32),
		out:  make(chan []byte, 32),
		done: make(chan struct{}),
	}
}

func (d *parityTun) Read(p []byte) (int, error) {
	select {
	case packet := <-d.in:
		return copy(p, packet), nil
	case <-d.done:
		return 0, net.ErrClosed
	}
}

func (d *parityTun) Write(p []byte) (int, error) {
	select {
	case d.out <- append([]byte(nil), p...):
		return len(p), nil
	case <-d.done:
		return 0, net.ErrClosed
	}
}

func (d *parityTun) Close() error {
	d.once.Do(func() { close(d.done) })
	return nil
}

// parityLegacyHandler implements tun.Handler, the legacy stack's contract.
type parityLegacyHandler struct{ parityRecorder }

func (h *parityLegacyHandler) PrepareConnection(string, M.Socksaddr, M.Socksaddr, tun.DirectRouteContext, time.Duration) (tun.DirectRouteDestination, error) {
	return nil, nil
}

func (h *parityLegacyHandler) NewConnection(_ context.Context, conn net.Conn, m M.Metadata) error {
	h.add(flowFrom("tcp", m))
	return conn.Close()
}

func (h *parityLegacyHandler) NewPacket(_ context.Context, _ netip.AddrPort, b *buf.Buffer, m M.Metadata, _ func(N.PacketConn) N.PacketWriter) {
	h.add(flowFrom("udp", m))
	b.Release()
}

func (h *parityLegacyHandler) NewError(context.Context, error) {}

// parityGoHandler implements GoStackHandler, the go stack's contract.
type parityGoHandler struct{ parityRecorder }

func (h *parityGoHandler) ShouldHijackDns(netip.AddrPort) bool { return false }

func (h *parityGoHandler) NewConnection(_ context.Context, conn net.Conn, m M.Metadata) error {
	h.add(flowFrom("tcp", m))
	// The go stack hands the handshake to the read side: a handler that
	// never reads leaves the connection waiting, so keep the connection
	// alive and drain it the way the existing flow tests do.
	if conn != nil {
		go func() {
			buffer := make([]byte, 4096)
			for {
				if _, err := conn.Read(buffer); err != nil {
					return
				}
			}
		}()
	}
	return nil
}

func (h *parityGoHandler) NewPacketConnection(_ context.Context, _ N.PacketConn, m M.Metadata) error {
	h.add(flowFrom("udp", m))
	return nil
}

// parityTraffic is the fixed set of datagrams fed to both stacks. Three
// distinct sessions, including one to an address outside the tunnel's own
// subnet, so a stack that only handles its own address cannot pass by luck.
func parityTraffic() [][]byte {
	return [][]byte{
		udpPacket(
			netip.MustParseAddrPort("172.19.0.2:40000"),
			netip.MustParseAddrPort("172.19.0.1:53"),
			[]byte("first"),
		),
		udpPacket(
			netip.MustParseAddrPort("172.19.0.2:40001"),
			netip.MustParseAddrPort("172.19.0.1:53"),
			[]byte("second"),
		),
		udpPacket(
			netip.MustParseAddrPort("172.19.0.2:40002"),
			netip.MustParseAddrPort("8.8.8.8:53"),
			[]byte("third"),
		),
	}
}

func legacyParityStack(t *testing.T) (*parityLegacyHandler, *parityTun) {
	t.Helper()
	device := newParityTun()
	handler := &parityLegacyHandler{}
	stack, err := tun.NewStack("mips", tun.StackOptions{
		Context: context.Background(),
		Tun:     device,
		TunOptions: tun.Options{
			MTU:          1500,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		},
		Handler:     handler,
		Logger:      logger.NOP(),
		UDPTimeout:  30 * time.Second,
		ICMPTimeout: 50 * time.Millisecond,
	})
	require.NoError(t, err)
	require.NoError(t, stack.Start())
	t.Cleanup(func() {
		_ = stack.Close()
		_ = device.Close()
	})
	return handler, device
}

func goParityStack(t *testing.T) (*parityGoHandler, *gotun.MemoryTun, <-chan []byte) {
	t.Helper()
	handler := &parityGoHandler{}
	outbound := make(chan []byte, 32)
	device := gotun.NewMemoryTun(gotun.MemoryTunOptions{
		MTU: 1500,
		Outbound: func(packets []*gobuf.Buffer) {
			for _, packet := range packets {
				select {
				case outbound <- append([]byte(nil), packet.Bytes()...):
				default:
				}
				packet.Release()
			}
		},
	})

	original := goStackDeviceFactory
	goStackDeviceFactory = func(gotun.Options) (gotun.Tun, error) { return device, nil }
	t.Cleanup(func() { goStackDeviceFactory = original })

	stack, err := buildGoStack(GoStackOptions{
		Context: context.Background(),
		DeviceOptions: tun.Options{
			Name:         "go-stack-parity",
			MTU:          1500,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
		},
		Handler:    handler,
		UDPTimeout: 30 * time.Second,
	})
	require.NoError(t, err)
	require.NoError(t, stack.Start())
	t.Cleanup(func() { _ = stack.Close() })
	return handler, device, outbound
}

func waitForFlows(t *testing.T, handler *parityRecorder, want int) []parityFlow {
	t.Helper()
	require.Eventually(t, func() bool {
		return len(handler.snapshot()) >= want
	}, 5*time.Second, 10*time.Millisecond)
	return handler.snapshot()
}

// The P2 gate's first end-to-end slice: the same datagrams through both
// stacks must hand the core the same sessions. Both stacks use one handler,
// so a difference here is a difference in the stack, not in the rules.
func TestGoStackAndLegacyHandOverTheSameUdpSessions(t *testing.T) {
	packets := parityTraffic()

	legacyHandler, legacyDevice := legacyParityStack(t)
	for _, packet := range packets {
		legacyDevice.in <- packet
	}
	legacy := waitForFlows(t, &legacyHandler.parityRecorder, len(packets))

	goHandler, goDevice, _ := goParityStack(t)
	require.NoError(t, goDevice.WaitWritePackets(packets))
	goSide := waitForFlows(t, &goHandler.parityRecorder, len(packets))

	assert.ElementsMatch(t, legacy, goSide,
		"the two stacks must hand the same UDP sessions to the core")
}

// paritySynAck waits for the stack's SYN+ACK, skipping any other packet the
// stack may put on the device first (an ICMP reply, for instance).
func paritySynAck(outbound <-chan []byte) []byte {
	deadline := time.After(10 * time.Second)
	for {
		select {
		case packet := <-outbound:
			if len(packet) >= 40 && packet[9] == 6 && packet[33] == 0x12 {
				return packet
			}
		case <-deadline:
			return nil
		}
	}
}

// parityTcpHandshake drives one connection to the point where the stack
// hands it over. The sequence numbers come from the stack's own SYN+ACK, so
// neither stack is assumed to pick a particular initial number.
func parityTcpHandshake(t *testing.T, write func([]byte) error, outbound <-chan []byte) {
	t.Helper()
	const clientSequence = uint32(1000)
	source := netip.MustParseAddrPort("172.19.0.2:41000")
	destination := netip.MustParseAddrPort("172.19.0.1:80")

	require.NoError(t, write(tcpSegment(source, destination, clientSequence, 0, 0x02, nil)))
	answer := paritySynAck(outbound)
	require.NotNil(t, answer, "the stack did not answer the TCP handshake")
	serverSequence := binary.BigEndian.Uint32(answer[24:28])
	require.Equal(t, clientSequence+1, binary.BigEndian.Uint32(answer[28:32]))
	require.NoError(t, write(tcpSegment(source, destination, clientSequence+1, serverSequence+1, 0x10, nil)))
}

// The P2 gate's second slice: the same TCP handshake through both stacks
// must produce the same connection count and the same five-tuple.
func TestGoStackAndLegacyHandOverTheSameTcpConnection(t *testing.T) {
	legacyHandler, legacyDevice := legacyParityStack(t)
	parityTcpHandshake(t, func(packet []byte) error {
		legacyDevice.in <- packet
		return nil
	}, legacyDevice.out)
	legacy := waitForFlows(t, &legacyHandler.parityRecorder, 1)

	goHandler, goDevice, outbound := goParityStack(t)
	parityTcpHandshake(t, func(packet []byte) error {
		return goDevice.WaitWritePackets([][]byte{packet})
	}, outbound)
	goSide := waitForFlows(t, &goHandler.parityRecorder, 1)

	assert.ElementsMatch(t, legacy, goSide,
		"the two stacks must hand the same TCP connection to the core")
}
