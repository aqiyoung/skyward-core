//go:build with_go_stack

// The go stack is sing-box 1.15's TCP/IP stack, written in Go. It replaces the
// user space stack that the tunnel used before: gVisor, mips, the system
// stack and the mixed stack all run a TCP/IP implementation that was written
// for something else, and the go stack is the one that was written for a
// tunnel.
//
// The build tag is what keeps it out of the releases for now. A build
// without it refuses the stack by name, so a configuration that asks for the
// go stack either gets it or says it cannot have it.

package sing_tun

import (
	"context"
	"net"
	"net/netip"

	gotun "github.com/sagernet/sing-tun"
	gobuf "github.com/sagernet/sing/common/buf"
	goM "github.com/sagernet/sing/common/metadata"
	goN "github.com/sagernet/sing/common/network"
	goRanges "github.com/sagernet/sing/common/ranges"
	"syscall"

	tun "github.com/metacubex/sing-tun"
	"github.com/metacubex/sing/common/buf"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"

	"github.com/metacubex/mihomo/component/resolver"
	"github.com/metacubex/mihomo/log"
)

func init() {
	SetGoStackFactory(buildGoStack)
}

// goStack is the stack and the device it owns.
type goStack struct {
	stack  *gotun.Go
	device gotun.Tun
}

func (s *goStack) Start() error {
	return s.stack.Start()
}

func (s *goStack) Close() error {
	return E.Errors(s.stack.Close(), s.device.Close())
}

// Device is the tunnel device. Closing it is the stack's work: the stack
// reads and writes through it, so it belongs to the stack.
func (s *goStack) Device() tun.Tun {
	return goStackDevice{Tun: s.device}
}

// goStackDevice presents the device the go stack owns to the rest of the
// listener. Its Close does nothing, because the stack closes the device.
type goStackDevice struct {
	gotun.Tun
}

func (d goStackDevice) Close() error {
	return nil
}

// goStackDeviceFactory opens the tunnel device. A test replaces it with a
// device it can drive, so the stack can be exercised without the system's
// privileges.
var goStackDeviceFactory = func(options gotun.Options) (gotun.Tun, error) {
	return gotun.New(options)
}

func buildGoStack(options GoStackOptions) (GoStack, error) {
	deviceOptions := goStackDeviceOptions(options)
	device, err := goStackDeviceFactory(deviceOptions)
	if err != nil {
		return nil, E.Cause(err, "go stack: open the tun device")
	}

	mapping := gotun.NATMappingAddressAndPortDependent
	filtering := gotun.NATFilteringAddressAndPortDependent
	if options.EndpointIndependentNat {
		mapping = gotun.NATMappingEndpointIndependent
		filtering = gotun.NATFilteringEndpointIndependent
	}

	stackOptions := gotun.StackOptions{}
	stackOptions.Context = options.Context
	stackOptions.Tun = device
	stackOptions.TunOptions = deviceOptions
	stackOptions.UDPTimeout = options.UDPTimeout
	stackOptions.ICMPTimeout = options.ICMPTimeout
	stackOptions.UDPMapping = mapping
	stackOptions.UDPFiltering = filtering
	stackOptions.Handler = goStackHandler{handler: options.Handler}
	stackOptions.Logger = goStackLogger{}
	stackOptions.ForwarderBindInterface = options.ForwarderBindInterface
	stackOptions.TCPCongestionControl = goStackCongestion(options.CongestionControl)

	stack, err := gotun.NewGo(stackOptions)
	if err != nil {
		_ = device.Close()
		return nil, E.Cause(err, "go stack: build the stack")
	}
	return &goStack{stack: stack, device: device}, nil
}

// goStackDeviceOptions turns the tunnel's settings into the ones the go
// stack's device understands.
//
// Two settings do not cross: the interface monitor, because the two stacks
// do not share a type for it, and the port ranges, which the go stack does
// not have. The stack finds the interface on its own, and the port ranges
// only ever narrowed what the tunnel carried.
func goStackDeviceOptions(options GoStackOptions) gotun.Options {
	device := options.DeviceOptions
	translated := gotun.Options{}
	translated.Name = device.Name
	translated.Inet4Address = device.Inet4Address
	translated.Inet6Address = device.Inet6Address
	translated.MTU = device.MTU
	translated.GSO = device.GSO
	translated.AutoRoute = device.AutoRoute
	translated.Inet4Gateway = device.Inet4Gateway
	translated.Inet6Gateway = device.Inet6Gateway
	translated.DNSMode = device.DNSMode
	translated.DNSAddress = device.DNSServers
	translated.IPRoute2TableIndex = device.IPRoute2TableIndex
	translated.IPRoute2RuleIndex = device.IPRoute2RuleIndex
	translated.IPRoute2AutoRedirectFallbackRuleIndex = device.IPRoute2AutoRedirectFallbackRuleIndex
	translated.AutoRedirectMarkMode = device.AutoRedirectMarkMode
	translated.AutoRedirectInputMark = device.AutoRedirectInputMark
	translated.AutoRedirectOutputMark = device.AutoRedirectOutputMark
	translated.ExcludeMPTCP = device.ExcludeMPTCP
	translated.Inet4LoopbackAddress = device.Inet4LoopbackAddress
	translated.Inet6LoopbackAddress = device.Inet6LoopbackAddress
	translated.StrictRoute = device.StrictRoute
	translated.Inet4RouteAddress = device.Inet4RouteAddress
	translated.Inet6RouteAddress = device.Inet6RouteAddress
	translated.Inet4RouteExcludeAddress = device.Inet4RouteExcludeAddress
	translated.Inet6RouteExcludeAddress = device.Inet6RouteExcludeAddress
	translated.IncludeInterface = device.IncludeInterface
	translated.ExcludeInterface = device.ExcludeInterface
	translated.IncludeAndroidUser = device.IncludeAndroidUser
	translated.IncludePackage = device.IncludePackage
	translated.ExcludePackage = device.ExcludePackage
	translated.IncludeMACAddress = device.IncludeMACAddress
	translated.ExcludeMACAddress = device.ExcludeMACAddress
	translated.FileDescriptor = device.FileDescriptor
	translated.Logger = goStackLogger{}
	// A descriptor that came from outside is already configured: the system
	// set its addresses and its routes before the tunnel started.
	translated.EXP_ExternalConfiguration = device.FileDescriptor != 0
	translated.EXP_MultiPendingPackets = true
	for _, uidRange := range device.IncludeUID {
		translated.IncludeUID = append(translated.IncludeUID, goRanges.Range[uint32]{Start: uidRange.Start, End: uidRange.End})
	}
	for _, uidRange := range device.ExcludeUID {
		translated.ExcludeUID = append(translated.ExcludeUID, goRanges.Range[uint32]{Start: uidRange.Start, End: uidRange.End})
	}
	return translated
}

// goStackCongestion names the congestion control the go stack knows. The
// stack calls its bbr bbr, so the name the configuration uses for the newer
// variant is translated.
func goStackCongestion(name string) string {
	if name == "bbr3" {
		return "bbr"
	}
	return name
}

// goStackHandler carries the traffic to the core's handler.
//
// The stack does not decide where a connection goes. It asks whether the
// connection may be made, and then hands the connection to the core, whose
// handler does the routing: the rules, the sniffing, the outbound. That
// keeps the two stacks on one set of rules.
type goStackHandler struct {
	handler GoStackHandler
}

func (h goStackHandler) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) gotun.FlowVerdict {
	if network == syscall.IPPROTO_UDP && h.handler != nil && h.handler.ShouldHijackDns(destination) {
		return gotun.FlowVerdict{Action: gotun.ActionHijackDNS}
	}
	return gotun.FlowVerdict{Action: gotun.ActionAccept}
}

func (h goStackHandler) NewDNSPacket(payload []byte, source goM.Socksaddr, destination goM.Socksaddr, writer goN.PacketWriter) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDnsRelayTimeout)
		defer cancel()
		reply := gobuf.NewSize(resolver.SafeDnsPacketSize)
		message, err := resolver.RelayDnsPacket(ctx, payload, reply.FreeBytes())
		if err != nil {
			reply.Release()
			return
		}
		reply.Truncate(len(message))
		_ = writer.WritePacket(reply, destination)
	}()
}

func (h goStackHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source goM.Socksaddr, destination goM.Socksaddr, onClose goN.CloseHandlerFunc) {
	err := h.handler.NewConnection(ctx, conn, M.Metadata{
		Source:      fromGoSocksaddr(source),
		Destination: fromGoSocksaddr(destination),
	})
	if onClose != nil {
		onClose(err)
	}
}

func (h goStackHandler) NewPacketConnectionEx(ctx context.Context, conn goN.PacketConn, source goM.Socksaddr, destination goM.Socksaddr, onClose goN.CloseHandlerFunc) {
	err := h.handler.NewPacketConnection(ctx, goPacketConn{PacketConn: conn}, M.Metadata{
		Source:      fromGoSocksaddr(source),
		Destination: fromGoSocksaddr(destination),
	})
	if onClose != nil {
		onClose(err)
	}
}

// goPacketConn presents the stack's packet connection to the core's handler.
// The two stacks carry their own buffers, so a packet crosses here once, as
// bytes.
type goPacketConn struct {
	goN.PacketConn
}

func (c goPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	packet := gobuf.NewSize(buffer.FreeLen())
	destination, err := c.PacketConn.ReadPacket(packet)
	if err != nil {
		packet.Release()
		return M.Socksaddr{}, err
	}
	_, err = buffer.Write(packet.Bytes())
	packet.Release()
	return fromGoSocksaddr(destination), err
}

func (c goPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	packet := gobuf.NewSize(buffer.Len())
	_, _ = packet.Write(buffer.Bytes())
	defer packet.Release()
	return c.PacketConn.WritePacket(packet, toGoSocksaddr(destination))
}

func fromGoSocksaddr(address goM.Socksaddr) M.Socksaddr {
	return M.Socksaddr{Addr: address.Addr, Port: address.Port, Fqdn: address.Fqdn}
}

func toGoSocksaddr(address M.Socksaddr) goM.Socksaddr {
	return goM.Socksaddr{Addr: address.Addr, Port: address.Port, Fqdn: address.Fqdn}
}

// goStackLogger writes the stack's own log lines through the core's logger.
type goStackLogger struct{}

func (l goStackLogger) Trace(args ...any) { log.SingLogger.Trace(args...) }
func (l goStackLogger) Debug(args ...any) { log.SingLogger.Debug(args...) }
func (l goStackLogger) Info(args ...any)  { log.SingLogger.Info(args...) }
func (l goStackLogger) Warn(args ...any)  { log.SingLogger.Warn(args...) }
func (l goStackLogger) Error(args ...any) { log.SingLogger.Error(args...) }
func (l goStackLogger) Fatal(args ...any) { log.SingLogger.Fatal(args...) }
func (l goStackLogger) Panic(args ...any) { log.SingLogger.Panic(args...) }
