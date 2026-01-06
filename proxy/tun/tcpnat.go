//go:build ios

package tun

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// TCPNat manages TCP NAT sessions for the system stack
type TCPNat struct {
	ctx       context.Context
	timeout   time.Duration
	portIndex uint16
	mu        sync.RWMutex
	addrMap   map[netip.AddrPort]uint16 // source → NAT port
	portMap   map[uint16]*NatSession    // NAT port → session
}

// NatSession represents a NAT session
type NatSession struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
	LastActive  time.Time
}

// NewTCPNat creates a new TCP NAT manager
func NewTCPNat(ctx context.Context, timeout time.Duration) *TCPNat {
	nat := &TCPNat{
		ctx:       ctx,
		timeout:   timeout,
		portIndex: 10000,
		addrMap:   make(map[netip.AddrPort]uint16),
		portMap:   make(map[uint16]*NatSession),
	}
	go nat.cleanupLoop()
	return nat
}

// cleanupLoop periodically removes expired sessions
func (n *TCPNat) cleanupLoop() {
	ticker := time.NewTicker(n.timeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			n.cleanup()
		case <-n.ctx.Done():
			return
		}
	}
}

// cleanup removes expired sessions
func (n *TCPNat) cleanup() {
	now := time.Now()
	n.mu.Lock()
	defer n.mu.Unlock()

	for port, session := range n.portMap {
		if now.Sub(session.LastActive) > n.timeout {
			delete(n.addrMap, session.Source)
			delete(n.portMap, port)
		}
	}
}

// Lookup finds or creates a NAT mapping for the given source/destination
// Returns the NAT port to use
func (n *TCPNat) Lookup(source, destination netip.AddrPort) (uint16, bool) {
	// Check existing mapping
	n.mu.RLock()
	port, exists := n.addrMap[source]
	n.mu.RUnlock()

	if exists {
		// Update last active time
		n.mu.Lock()
		if session, ok := n.portMap[port]; ok {
			session.LastActive = time.Now()
		}
		n.mu.Unlock()
		return port, false // false = existing session
	}

	// Create new mapping
	n.mu.Lock()
	defer n.mu.Unlock()

	// Double check after acquiring write lock
	if port, exists = n.addrMap[source]; exists {
		return port, false
	}

	// Allocate new port
	port = n.nextPort()
	n.addrMap[source] = port
	n.portMap[port] = &NatSession{
		Source:      source,
		Destination: destination,
		LastActive:  time.Now(),
	}

	return port, true // true = new session
}

// LookupBack finds a session by NAT port (for reverse NAT)
func (n *TCPNat) LookupBack(port uint16) *NatSession {
	n.mu.RLock()
	session := n.portMap[port]
	n.mu.RUnlock()

	if session != nil {
		n.mu.Lock()
		session.LastActive = time.Now()
		n.mu.Unlock()
	}

	return session
}

// Delete removes a NAT mapping
func (n *TCPNat) Delete(source netip.AddrPort) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if port, exists := n.addrMap[source]; exists {
		delete(n.addrMap, source)
		delete(n.portMap, port)
	}
}

// nextPort returns the next available NAT port (must be called with lock held)
func (n *TCPNat) nextPort() uint16 {
	port := n.portIndex
	n.portIndex++
	if n.portIndex == 0 || n.portIndex < 10000 {
		n.portIndex = 10000
	}

	// Skip ports that are already in use
	for _, exists := n.portMap[port]; exists; _, exists = n.portMap[port] {
		port = n.portIndex
		n.portIndex++
		if n.portIndex == 0 || n.portIndex < 10000 {
			n.portIndex = 10000
		}
	}

	return port
}

// UDPNat manages UDP NAT sessions
type UDPNat struct {
	ctx     context.Context
	timeout time.Duration
	mu      sync.RWMutex
	sessions map[udpSessionKey]*UDPSession
}

type udpSessionKey struct {
	srcAddr [16]byte
	dstAddr [16]byte
	srcPort uint16
	dstPort uint16
	isIPv6  bool
}

// UDPSession represents a UDP NAT session
type UDPSession struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
	LastActive  time.Time
}

// NewUDPNat creates a new UDP NAT manager
func NewUDPNat(ctx context.Context, timeout time.Duration) *UDPNat {
	nat := &UDPNat{
		ctx:      ctx,
		timeout:  timeout,
		sessions: make(map[udpSessionKey]*UDPSession),
	}
	go nat.cleanupLoop()
	return nat
}

func (n *UDPNat) cleanupLoop() {
	ticker := time.NewTicker(n.timeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			n.cleanup()
		case <-n.ctx.Done():
			return
		}
	}
}

func (n *UDPNat) cleanup() {
	now := time.Now()
	n.mu.Lock()
	defer n.mu.Unlock()

	for key, session := range n.sessions {
		if now.Sub(session.LastActive) > n.timeout {
			delete(n.sessions, key)
		}
	}
}

// Lookup finds or creates a UDP session
func (n *UDPNat) Lookup(source, destination netip.AddrPort) (*UDPSession, bool) {
	key := makeUDPKey(source, destination)

	n.mu.RLock()
	session, exists := n.sessions[key]
	n.mu.RUnlock()

	if exists {
		n.mu.Lock()
		session.LastActive = time.Now()
		n.mu.Unlock()
		return session, false
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// Double check
	if session, exists = n.sessions[key]; exists {
		session.LastActive = time.Now()
		return session, false
	}

	session = &UDPSession{
		Source:      source,
		Destination: destination,
		LastActive:  time.Now(),
	}
	n.sessions[key] = session
	return session, true
}

func makeUDPKey(source, destination netip.AddrPort) udpSessionKey {
	key := udpSessionKey{
		srcPort: source.Port(),
		dstPort: destination.Port(),
		isIPv6:  source.Addr().Is6(),
	}
	copy(key.srcAddr[:], source.Addr().AsSlice())
	copy(key.dstAddr[:], destination.Addr().AsSlice())
	return key
}
