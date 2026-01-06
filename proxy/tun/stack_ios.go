//go:build ios

package tun

import (
	"context"
	"io"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/buf"
	c "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
)

// SystemStack implements a system-based TCP/IP stack for iOS
// It uses NAT and a local TCP listener to handle connections through the system TCP stack
type SystemStack struct {
	ctx    context.Context
	cancel context.CancelFunc

	tun     *IOSTun
	handler *Handler

	// TUN addresses
	inet4Addr netip.Addr // TUN interface address (e.g., 10.0.0.1)
	inet4Next netip.Addr // NAT source address (e.g., 10.0.0.2)
	inet6Addr netip.Addr
	inet6Next netip.Addr

	// TCP NAT and listener
	tcpNat       *TCPNat
	tcpListener  net.Listener
	tcpListener6 net.Listener
	tcpPort      uint16
	tcpPort6     uint16

	// UDP NAT
	udpNat *UDPNat

	// Synchronization
	wg     sync.WaitGroup
	closed bool
	mu     sync.Mutex
}

// NewStack creates a new iOS system stack
func NewStack(ctx context.Context, options StackOptions, handler *Handler) (Stack, error) {
	// Default TUN addresses
	inet4Addr := netip.MustParseAddr("10.0.0.1")
	inet4Next := netip.MustParseAddr("10.0.0.2")
	inet6Addr := netip.MustParseAddr("fd00::1")
	inet6Next := netip.MustParseAddr("fd00::2")

	ctx, cancel := context.WithCancel(ctx)

	idleTimeout := options.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = 5 * time.Minute
	}

	iosTun, ok := options.Tun.(*IOSTun)
	if !ok {
		cancel()
		return nil, errors.New("expected IOSTun for iOS stack")
	}

	stack := &SystemStack{
		ctx:       ctx,
		cancel:    cancel,
		tun:       iosTun,
		handler:   handler,
		inet4Addr: inet4Addr,
		inet4Next: inet4Next,
		inet6Addr: inet6Addr,
		inet6Next: inet6Next,
		tcpNat:    NewTCPNat(ctx, idleTimeout),
		udpNat:    NewUDPNat(ctx, idleTimeout),
	}

	errors.LogInfo(ctx, "iOS system stack created")
	return stack, nil
}

// Start starts the system stack
func (s *SystemStack) Start() error {
	// Start IPv4 TCP listener
	listener, err := net.Listen("tcp4", net.JoinHostPort(s.inet4Addr.String(), "0"))
	if err != nil {
		// If we can't bind to TUN address, try localhost
		listener, err = net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return errors.New("failed to start TCP listener: ", err)
		}
	}
	s.tcpListener = listener
	s.tcpPort = uint16(listener.Addr().(*net.TCPAddr).Port)

	// Start IPv6 TCP listener (optional)
	listener6, err := net.Listen("tcp6", net.JoinHostPort(s.inet6Addr.String(), "0"))
	if err == nil {
		s.tcpListener6 = listener6
		s.tcpPort6 = uint16(listener6.Addr().(*net.TCPAddr).Port)
	}

	// Start goroutines
	s.wg.Add(2)
	go s.tunLoop()
	go s.acceptLoop(s.tcpListener, false)

	if s.tcpListener6 != nil {
		s.wg.Add(1)
		go s.acceptLoop(s.tcpListener6, true)
	}

	errors.LogInfo(s.ctx, "iOS system stack started, TCP port: ", s.tcpPort)
	return nil
}

// Close stops the system stack
func (s *SystemStack) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	s.cancel()

	if s.tcpListener != nil {
		s.tcpListener.Close()
	}
	if s.tcpListener6 != nil {
		s.tcpListener6.Close()
	}

	s.wg.Wait()

	errors.LogInfo(s.ctx, "iOS system stack closed")
	return nil
}

// tunLoop reads packets from TUN and processes them
func (s *SystemStack) tunLoop() {
	defer s.wg.Done()
	defer debug.FreeOSMemory()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		if s.tun.IsClosed() {
			return
		}

		packet, proto, err := s.tun.ReadPacket()
		if err != nil {
			if err == io.EOF || s.tun.IsClosed() {
				return
			}
			continue
		}

		if len(packet) == 0 {
			continue
		}

		// Process and possibly write back
		if s.processPacket(packet, proto) {
			s.tun.WritePacket(packet, proto)
		}
	}
}

// processPacket processes an IP packet
func (s *SystemStack) processPacket(packet []byte, proto int) bool {
	version := IPVersion(packet)

	switch version {
	case 4:
		return s.processIPv4(packet)
	case 6:
		return s.processIPv6(packet)
	}

	return false
}

// processIPv4 processes an IPv4 packet
func (s *SystemStack) processIPv4(packet []byte) bool {
	if len(packet) < IPv4MinHeaderSize {
		return false
	}

	ipHdr := IPv4Header(packet)
	headerLen := ipHdr.HeaderLength()
	if len(packet) < headerLen {
		return false
	}

	payload := ipHdr.Payload()
	if len(payload) == 0 {
		return false
	}

	switch ipHdr.Protocol() {
	case ProtocolTCP:
		return s.processTCPv4(ipHdr, TCPHeader(payload))
	case ProtocolUDP:
		s.processUDPv4(ipHdr, UDPHeader(payload))
		return false
	}

	return false
}

// processIPv6 processes an IPv6 packet
func (s *SystemStack) processIPv6(packet []byte) bool {
	if len(packet) < IPv6HeaderSize {
		return false
	}

	ipHdr := IPv6Header(packet)
	payload := ipHdr.Payload()
	if len(payload) == 0 {
		return false
	}

	switch ipHdr.NextHeader() {
	case ProtocolTCP:
		return s.processTCPv6(ipHdr, TCPHeader(payload))
	case ProtocolUDP:
		s.processUDPv6(ipHdr, UDPHeader(payload))
		return false
	}

	return false
}

// processTCPv4 processes a TCP packet over IPv4
func (s *SystemStack) processTCPv4(ipHdr IPv4Header, tcpHdr TCPHeader) bool {
	if len(tcpHdr) < TCPMinHeaderSize {
		return false
	}

	srcAddr := ipHdr.SourceAddr()
	dstAddr := ipHdr.DestinationAddr()
	srcPort := tcpHdr.SourcePort()
	dstPort := tcpHdr.DestinationPort()

	source := netip.AddrPortFrom(srcAddr, srcPort)
	destination := netip.AddrPortFrom(dstAddr, dstPort)

	// Check if this is a response from our local listener
	if srcAddr == s.inet4Addr && srcPort == s.tcpPort {
		// Reverse NAT: lookup original destination by NAT port
		session := s.tcpNat.LookupBack(dstPort)
		if session == nil {
			return false
		}

		// Rewrite packet: src=original_dst, dst=original_src
		ipHdr.SetSourceAddr(session.Destination.Addr())
		tcpHdr.SetSourcePort(session.Destination.Port())
		ipHdr.SetDestinationAddr(session.Source.Addr())
		tcpHdr.SetDestinationPort(session.Source.Port())

		// Recalculate checksums
		s.recalcTCPv4Checksum(ipHdr, tcpHdr)
		return true
	}

	// Handle FIN/RST - delete NAT entry
	flags := tcpHdr.Flags()
	if flags&(TCPFlagFIN|TCPFlagRST) != 0 {
		s.tcpNat.Delete(source)
	}

	// Outgoing packet - apply NAT
	natPort, isNew := s.tcpNat.Lookup(source, destination)

	// Rewrite packet: src=inet4Next:natPort, dst=inet4Addr:tcpPort
	ipHdr.SetSourceAddr(s.inet4Next)
	tcpHdr.SetSourcePort(natPort)
	ipHdr.SetDestinationAddr(s.inet4Addr)
	tcpHdr.SetDestinationPort(s.tcpPort)

	// Recalculate checksums
	s.recalcTCPv4Checksum(ipHdr, tcpHdr)

	if isNew {
		errors.LogDebug(s.ctx, "TCP NAT: ", source, " -> ", destination, " (port ", natPort, ")")
	}

	return true
}

// processTCPv6 processes a TCP packet over IPv6
func (s *SystemStack) processTCPv6(ipHdr IPv6Header, tcpHdr TCPHeader) bool {
	if len(tcpHdr) < TCPMinHeaderSize {
		return false
	}

	if s.tcpListener6 == nil {
		return false
	}

	srcAddr := ipHdr.SourceAddr()
	dstAddr := ipHdr.DestinationAddr()
	srcPort := tcpHdr.SourcePort()
	dstPort := tcpHdr.DestinationPort()

	source := netip.AddrPortFrom(srcAddr, srcPort)
	destination := netip.AddrPortFrom(dstAddr, dstPort)

	// Check if this is a response from our local listener
	if srcAddr == s.inet6Addr && srcPort == s.tcpPort6 {
		session := s.tcpNat.LookupBack(dstPort)
		if session == nil {
			return false
		}

		ipHdr.SetSourceAddr(session.Destination.Addr())
		tcpHdr.SetSourcePort(session.Destination.Port())
		ipHdr.SetDestinationAddr(session.Source.Addr())
		tcpHdr.SetDestinationPort(session.Source.Port())

		s.recalcTCPv6Checksum(ipHdr, tcpHdr)
		return true
	}

	// Handle FIN/RST
	flags := tcpHdr.Flags()
	if flags&(TCPFlagFIN|TCPFlagRST) != 0 {
		s.tcpNat.Delete(source)
	}

	// Outgoing packet - apply NAT
	natPort, _ := s.tcpNat.Lookup(source, destination)

	ipHdr.SetSourceAddr(s.inet6Next)
	tcpHdr.SetSourcePort(natPort)
	ipHdr.SetDestinationAddr(s.inet6Addr)
	tcpHdr.SetDestinationPort(s.tcpPort6)

	s.recalcTCPv6Checksum(ipHdr, tcpHdr)
	return true
}

// processUDPv4 processes a UDP packet over IPv4
func (s *SystemStack) processUDPv4(ipHdr IPv4Header, udpHdr UDPHeader) {
	if len(udpHdr) < UDPHeaderSize {
		return
	}

	srcAddr := ipHdr.SourceAddr()
	dstAddr := ipHdr.DestinationAddr()
	srcPort := udpHdr.SourcePort()
	dstPort := udpHdr.DestinationPort()

	source := netip.AddrPortFrom(srcAddr, srcPort)
	destination := netip.AddrPortFrom(dstAddr, dstPort)

	payload := udpHdr.Payload()
	if len(payload) == 0 {
		return
	}

	_, isNew := s.udpNat.Lookup(source, destination)
	if isNew {
		// New UDP session - dispatch to handler
		go s.handleUDPSession(source, destination, payload)
	}
}

// processUDPv6 processes a UDP packet over IPv6
func (s *SystemStack) processUDPv6(ipHdr IPv6Header, udpHdr UDPHeader) {
	if len(udpHdr) < UDPHeaderSize {
		return
	}

	srcAddr := ipHdr.SourceAddr()
	dstAddr := ipHdr.DestinationAddr()
	srcPort := udpHdr.SourcePort()
	dstPort := udpHdr.DestinationPort()

	source := netip.AddrPortFrom(srcAddr, srcPort)
	destination := netip.AddrPortFrom(dstAddr, dstPort)

	payload := udpHdr.Payload()
	if len(payload) == 0 {
		return
	}

	_, isNew := s.udpNat.Lookup(source, destination)
	if isNew {
		go s.handleUDPSession(source, destination, payload)
	}
}

// handleUDPSession handles a new UDP session
func (s *SystemStack) handleUDPSession(source, destination netip.AddrPort, payload []byte) {
	sid := session.NewID()
	ctx := c.ContextWithID(s.ctx, sid)

	dest := xnet.UDPDestination(
		xnet.IPAddress(destination.Addr().AsSlice()),
		xnet.Port(destination.Port()),
	)

	inbound := session.Inbound{
		Name:          "tun-ios",
		CanSpliceCopy: 1,
		Source:        xnet.UDPDestination(xnet.IPAddress(source.Addr().AsSlice()), xnet.Port(source.Port())),
		User: &protocol.MemoryUser{
			Level: s.handler.config.UserLevel,
		},
	}
	ctx = session.ContextWithInbound(ctx, &inbound)

	// Create a simple buffer with the payload
	reader := buf.FromBytes(payload)
	pReader, pWriter := io.Pipe()

	link := &transport.Link{
		Reader: buf.NewReader(pReader),
		Writer: buf.NewWriter(pWriter),
	}

	go func() {
		pWriter.Write(reader.Bytes())
		pWriter.Close()
	}()

	if err := s.handler.dispatcher.DispatchLink(ctx, dest, link); err != nil {
		errors.LogDebug(ctx, "UDP dispatch error: ", err)
	}
}

// acceptLoop accepts connections from the local TCP listener
func (s *SystemStack) acceptLoop(listener net.Listener, isIPv6 bool) {
	defer s.wg.Done()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				continue
			}
		}

		// Get the NAT port from the remote address
		remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
		natPort := uint16(remoteAddr.Port)

		// Lookup the original destination
		natSession := s.tcpNat.LookupBack(natPort)
		if natSession == nil {
			errors.LogDebug(s.ctx, "TCP accept: no NAT session for port ", natPort)
			conn.Close()
			continue
		}

		// Dispatch to handler
		dest := xnet.TCPDestination(
			xnet.IPAddress(natSession.Destination.Addr().AsSlice()),
			xnet.Port(natSession.Destination.Port()),
		)

		go s.handler.HandleConnection(conn, dest)
	}
}

// recalcTCPv4Checksum recalculates TCP and IPv4 checksums
func (s *SystemStack) recalcTCPv4Checksum(ipHdr IPv4Header, tcpHdr TCPHeader) {
	// Clear TCP checksum
	tcpHdr.SetChecksum(0)

	// Calculate pseudo-header checksum
	pseudoSum := PseudoHeaderChecksum(
		ProtocolTCP,
		ipHdr.SourceAddrSlice(),
		ipHdr.DestinationAddrSlice(),
		ipHdr.PayloadLength(),
	)

	// Calculate full TCP checksum
	fullChecksum := tcpHdr.CalculateChecksum(pseudoSum)
	tcpHdr.SetChecksum(^fullChecksum)

	// Recalculate IP header checksum
	ipHdr.SetChecksum(0)
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
}

// recalcTCPv6Checksum recalculates TCP checksum for IPv6
func (s *SystemStack) recalcTCPv6Checksum(ipHdr IPv6Header, tcpHdr TCPHeader) {
	// Clear TCP checksum
	tcpHdr.SetChecksum(0)

	// Calculate pseudo-header checksum
	pseudoSum := PseudoHeaderChecksum(
		ProtocolTCP,
		ipHdr.SourceAddrSlice(),
		ipHdr.DestinationAddrSlice(),
		ipHdr.PayloadLength(),
	)

	// Calculate full TCP checksum
	fullChecksum := tcpHdr.CalculateChecksum(pseudoSum)
	tcpHdr.SetChecksum(^fullChecksum)
}
