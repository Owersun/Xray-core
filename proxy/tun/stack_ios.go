//go:build ios

package tun

import (
	"context"
	"encoding/binary"
	"io"
	"net"
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

const (
	// IP header lengths
	ipv4MinHeaderLen = 20
	ipv6HeaderLen    = 40

	// Transport header lengths
	tcpMinHeaderLen = 20
	udpHeaderLen    = 8

	// IP protocols
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58

	// TCP flags
	tcpFlagSYN = 0x02
	tcpFlagACK = 0x10
	tcpFlagFIN = 0x01
	tcpFlagRST = 0x04
)

// tcpSessionKey uniquely identifies a TCP connection (5-tuple)
type tcpSessionKey struct {
	srcIP   [16]byte
	dstIP   [16]byte
	srcPort uint16
	dstPort uint16
	isIPv6  bool
}

// tcpSession represents an active TCP session
type tcpSession struct {
	key        tcpSessionKey
	conn       net.Conn
	reader     *buf.BufferedReader
	writer     buf.Writer
	lastActive time.Time
	closed     bool
	mu         sync.Mutex
}

// udpSessionKey uniquely identifies a UDP session
type udpSessionKey struct {
	srcIP   [16]byte
	dstIP   [16]byte
	srcPort uint16
	dstPort uint16
	isIPv6  bool
}

// udpSession represents an active UDP session
type udpSession struct {
	key        udpSessionKey
	conn       net.Conn
	lastActive time.Time
}

// LightweightStack is a memory-efficient TCP/IP stack for iOS
// It parses IP packets and creates connections via system TCP/UDP stack
type LightweightStack struct {
	ctx         context.Context
	cancel      context.CancelFunc
	tun         *IOSTun
	handler     *Handler
	idleTimeout time.Duration

	tcpSessions sync.Map // map[tcpSessionKey]*tcpSession
	udpSessions sync.Map // map[udpSessionKey]*udpSession

	wg     sync.WaitGroup
	closed bool
	mu     sync.Mutex
}

// NewStack creates a new iOS lightweight stack
func NewStack(ctx context.Context, options StackOptions, handler *Handler) (Stack, error) {
	iosTun, ok := options.Tun.(*IOSTun)
	if !ok {
		return nil, errors.New("expected IOSTun for iOS stack")
	}

	ctx, cancel := context.WithCancel(ctx)

	idleTimeout := options.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = 5 * time.Minute
	}

	stack := &LightweightStack{
		ctx:         ctx,
		cancel:      cancel,
		tun:         iosTun,
		handler:     handler,
		idleTimeout: idleTimeout,
	}

	errors.LogInfo(ctx, "iOS lightweight stack created")
	return stack, nil
}

// Start starts the packet processing loop
func (s *LightweightStack) Start() error {
	s.wg.Add(2)
	go s.readLoop()
	go s.cleanupLoop()

	errors.LogInfo(s.ctx, "iOS lightweight stack started")
	return nil
}

// Close stops the stack and cleans up resources
func (s *LightweightStack) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	s.cancel()

	// Close all TCP sessions
	s.tcpSessions.Range(func(key, value interface{}) bool {
		sess := value.(*tcpSession)
		sess.mu.Lock()
		if sess.conn != nil && !sess.closed {
			sess.conn.Close()
			sess.closed = true
		}
		sess.mu.Unlock()
		return true
	})

	// Close all UDP sessions
	s.udpSessions.Range(func(key, value interface{}) bool {
		sess := value.(*udpSession)
		if sess.conn != nil {
			sess.conn.Close()
		}
		return true
	})

	s.wg.Wait()
	errors.LogInfo(s.ctx, "iOS lightweight stack closed")
	return nil
}

// readLoop reads packets from TUN and processes them
func (s *LightweightStack) readLoop() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		if s.tun.IsClosed() {
			return
		}

		data, ipVersion, err := s.tun.ReadPacket()
		if err != nil {
			if err == io.EOF || s.tun.IsClosed() {
				return
			}
			errors.LogWarning(s.ctx, "read packet error: ", err)
			continue
		}

		if len(data) == 0 {
			continue
		}

		// Process packet in current goroutine to save memory
		// Only spawn goroutine for new TCP connections
		s.processPacket(data, ipVersion)
	}
}

// processPacket parses and handles an IP packet
func (s *LightweightStack) processPacket(packet []byte, ipVersion int) {
	var (
		srcIP, dstIP net.IP
		ipProto      uint8
		payload      []byte
		isIPv6       bool
	)

	// Parse IP header
	if ipVersion == 4 || (len(packet) > 0 && packet[0]>>4 == 4) {
		// IPv4
		if len(packet) < ipv4MinHeaderLen {
			return
		}
		headerLen := int(packet[0]&0x0f) * 4
		if headerLen < ipv4MinHeaderLen || len(packet) < headerLen {
			return
		}
		srcIP = net.IP(packet[12:16])
		dstIP = net.IP(packet[16:20])
		ipProto = packet[9]
		payload = packet[headerLen:]
		isIPv6 = false
	} else if ipVersion == 6 || (len(packet) > 0 && packet[0]>>4 == 6) {
		// IPv6
		if len(packet) < ipv6HeaderLen {
			return
		}
		srcIP = net.IP(packet[8:24])
		dstIP = net.IP(packet[24:40])
		ipProto = packet[6]
		payload = packet[ipv6HeaderLen:]
		isIPv6 = true
	} else {
		return
	}

	// Handle transport layer
	switch ipProto {
	case protoTCP:
		s.handleTCP(srcIP, dstIP, payload, isIPv6)
	case protoUDP:
		s.handleUDP(srcIP, dstIP, payload, isIPv6)
	case protoICMP, protoICMPv6:
		// Ignore ICMP for now
	}
}

// handleTCP processes TCP packets
func (s *LightweightStack) handleTCP(srcIP, dstIP net.IP, tcpData []byte, isIPv6 bool) {
	if len(tcpData) < tcpMinHeaderLen {
		return
	}

	srcPort := binary.BigEndian.Uint16(tcpData[0:2])
	dstPort := binary.BigEndian.Uint16(tcpData[2:4])
	dataOffset := int(tcpData[12]>>4) * 4
	flags := tcpData[13]

	if dataOffset < tcpMinHeaderLen || len(tcpData) < dataOffset {
		return
	}

	// Create session key
	key := tcpSessionKey{
		srcPort: srcPort,
		dstPort: dstPort,
		isIPv6:  isIPv6,
	}
	if isIPv6 {
		copy(key.srcIP[:], srcIP.To16())
		copy(key.dstIP[:], dstIP.To16())
	} else {
		copy(key.srcIP[:4], srcIP.To4())
		copy(key.dstIP[:4], dstIP.To4())
	}

	// Check for existing session
	if sessVal, ok := s.tcpSessions.Load(key); ok {
		sess := sessVal.(*tcpSession)
		sess.mu.Lock()
		sess.lastActive = time.Now()

		// Handle FIN/RST
		if flags&(tcpFlagFIN|tcpFlagRST) != 0 {
			if sess.conn != nil && !sess.closed {
				sess.conn.Close()
				sess.closed = true
			}
			sess.mu.Unlock()
			s.tcpSessions.Delete(key)
			return
		}

		sess.mu.Unlock()
		return
	}

	// Only create new session on SYN
	if flags&tcpFlagSYN == 0 {
		return
	}

	// Create new TCP session - dispatch to handler
	dest := xnet.TCPDestination(xnet.IPAddress(dstIP), xnet.Port(dstPort))

	// Create virtual connection for dispatcher
	go s.handleNewTCPConnection(key, srcIP, srcPort, dest)
}

// handleNewTCPConnection creates a new TCP session and dispatches it
func (s *LightweightStack) handleNewTCPConnection(key tcpSessionKey, srcIP net.IP, srcPort uint16, dest xnet.Destination) {
	sid := session.NewID()
	ctx := c.ContextWithID(s.ctx, sid)

	// Setup inbound session
	inbound := session.Inbound{
		Name:          "tun-ios",
		CanSpliceCopy: 1,
		Source:        xnet.TCPDestination(xnet.IPAddress(srcIP), xnet.Port(srcPort)),
		User: &protocol.MemoryUser{
			Level: s.handler.config.UserLevel,
		},
	}
	ctx = session.ContextWithInbound(ctx, &inbound)
	ctx = session.SubContextFromMuxInbound(ctx)

	// Create pipe for communication
	pReader, pWriter := io.Pipe()

	// Create session
	sess := &tcpSession{
		key:        key,
		lastActive: time.Now(),
	}
	s.tcpSessions.Store(key, sess)

	// Create link for dispatcher
	link := &transport.Link{
		Reader: buf.NewReader(pReader),
		Writer: buf.NewWriter(pWriter),
	}

	errors.LogInfo(ctx, "new TCP connection to ", dest)

	// Dispatch to routing
	if err := s.handler.dispatcher.DispatchLink(ctx, dest, link); err != nil {
		errors.LogWarning(ctx, "dispatch error: ", err)
		pReader.Close()
		pWriter.Close()
		s.tcpSessions.Delete(key)
		return
	}

	errors.LogInfo(ctx, "TCP connection completed")
	s.tcpSessions.Delete(key)
}

// handleUDP processes UDP packets
func (s *LightweightStack) handleUDP(srcIP, dstIP net.IP, udpData []byte, isIPv6 bool) {
	if len(udpData) < udpHeaderLen {
		return
	}

	srcPort := binary.BigEndian.Uint16(udpData[0:2])
	dstPort := binary.BigEndian.Uint16(udpData[2:4])
	length := binary.BigEndian.Uint16(udpData[4:6])

	if int(length) < udpHeaderLen || len(udpData) < int(length) {
		return
	}

	payload := udpData[udpHeaderLen:length]
	if len(payload) == 0 {
		return
	}

	// Create session key
	key := udpSessionKey{
		srcPort: srcPort,
		dstPort: dstPort,
		isIPv6:  isIPv6,
	}
	if isIPv6 {
		copy(key.srcIP[:], srcIP.To16())
		copy(key.dstIP[:], dstIP.To16())
	} else {
		copy(key.srcIP[:4], srcIP.To4())
		copy(key.dstIP[:4], dstIP.To4())
	}

	dest := xnet.UDPDestination(xnet.IPAddress(dstIP), xnet.Port(dstPort))

	// Check for existing session
	if sessVal, ok := s.udpSessions.Load(key); ok {
		sess := sessVal.(*udpSession)
		sess.lastActive = time.Now()
		// Write payload to existing connection
		if sess.conn != nil {
			sess.conn.Write(payload)
		}
		return
	}

	// Create new UDP session
	go s.handleNewUDPConnection(key, srcIP, srcPort, dest, payload)
}

// handleNewUDPConnection creates a new UDP session
func (s *LightweightStack) handleNewUDPConnection(key udpSessionKey, srcIP net.IP, srcPort uint16, dest xnet.Destination, initialPayload []byte) {
	sid := session.NewID()
	ctx := c.ContextWithID(s.ctx, sid)

	// Setup inbound session
	inbound := session.Inbound{
		Name:          "tun-ios",
		CanSpliceCopy: 1,
		Source:        xnet.UDPDestination(xnet.IPAddress(srcIP), xnet.Port(srcPort)),
		User: &protocol.MemoryUser{
			Level: s.handler.config.UserLevel,
		},
	}
	ctx = session.ContextWithInbound(ctx, &inbound)
	ctx = session.SubContextFromMuxInbound(ctx)

	// Create pipe for communication
	pReader, pWriter := io.Pipe()

	// Store session
	sess := &udpSession{
		key:        key,
		lastActive: time.Now(),
	}
	s.udpSessions.Store(key, sess)

	// Write initial payload
	go func() {
		pWriter.Write(initialPayload)
	}()

	// Create link for dispatcher
	link := &transport.Link{
		Reader: buf.NewReader(pReader),
		Writer: buf.NewWriter(pWriter),
	}

	errors.LogInfo(ctx, "new UDP connection to ", dest)

	// Dispatch to routing
	if err := s.handler.dispatcher.DispatchLink(ctx, dest, link); err != nil {
		errors.LogWarning(ctx, "dispatch error: ", err)
	}

	pReader.Close()
	pWriter.Close()
	s.udpSessions.Delete(key)
}

// cleanupLoop periodically cleans up idle sessions
func (s *LightweightStack) cleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.cleanup()
			// Also trigger GC to keep memory low
			debug.FreeOSMemory()
		}
	}
}

// cleanup removes idle sessions
func (s *LightweightStack) cleanup() {
	now := time.Now()

	// Cleanup TCP sessions
	s.tcpSessions.Range(func(k, v interface{}) bool {
		sess := v.(*tcpSession)
		sess.mu.Lock()
		if now.Sub(sess.lastActive) > s.idleTimeout {
			if sess.conn != nil && !sess.closed {
				sess.conn.Close()
				sess.closed = true
			}
			sess.mu.Unlock()
			s.tcpSessions.Delete(k)
			return true
		}
		sess.mu.Unlock()
		return true
	})

	// Cleanup UDP sessions
	s.udpSessions.Range(func(k, v interface{}) bool {
		sess := v.(*udpSession)
		if now.Sub(sess.lastActive) > s.idleTimeout {
			if sess.conn != nil {
				sess.conn.Close()
			}
			s.udpSessions.Delete(k)
		}
		return true
	})
}
