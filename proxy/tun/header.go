//go:build ios

package tun

import (
	"encoding/binary"
	"net/netip"
)

// IP protocol numbers
const (
	ProtocolICMP   = 1
	ProtocolTCP    = 6
	ProtocolUDP    = 17
	ProtocolICMPv6 = 58
)

// IP header sizes
const (
	IPv4MinHeaderSize = 20
	IPv6HeaderSize    = 40
)

// Transport header sizes
const (
	TCPMinHeaderSize = 20
	UDPHeaderSize    = 8
)

// TCP flags
const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
	TCPFlagURG = 0x20
)

// IPv4Header represents an IPv4 header
type IPv4Header []byte

// Version returns the IP version (should be 4)
func (h IPv4Header) Version() int {
	return int(h[0] >> 4)
}

// HeaderLength returns the header length in bytes
func (h IPv4Header) HeaderLength() int {
	return int(h[0]&0x0f) * 4
}

// TotalLength returns the total packet length
func (h IPv4Header) TotalLength() uint16 {
	return binary.BigEndian.Uint16(h[2:4])
}

// SetTotalLength sets the total packet length
func (h IPv4Header) SetTotalLength(length uint16) {
	binary.BigEndian.PutUint16(h[2:4], length)
}

// Protocol returns the protocol number
func (h IPv4Header) Protocol() uint8 {
	return h[9]
}

// Checksum returns the header checksum
func (h IPv4Header) Checksum() uint16 {
	return binary.BigEndian.Uint16(h[10:12])
}

// SetChecksum sets the header checksum
func (h IPv4Header) SetChecksum(checksum uint16) {
	binary.BigEndian.PutUint16(h[10:12], checksum)
}

// SourceAddr returns the source IP address
func (h IPv4Header) SourceAddr() netip.Addr {
	return netip.AddrFrom4([4]byte(h[12:16]))
}

// SetSourceAddr sets the source IP address
func (h IPv4Header) SetSourceAddr(addr netip.Addr) {
	copy(h[12:16], addr.AsSlice())
}

// DestinationAddr returns the destination IP address
func (h IPv4Header) DestinationAddr() netip.Addr {
	return netip.AddrFrom4([4]byte(h[16:20]))
}

// SetDestinationAddr sets the destination IP address
func (h IPv4Header) SetDestinationAddr(addr netip.Addr) {
	copy(h[16:20], addr.AsSlice())
}

// SourceAddrSlice returns source address as byte slice
func (h IPv4Header) SourceAddrSlice() []byte {
	return h[12:16]
}

// DestinationAddrSlice returns destination address as byte slice
func (h IPv4Header) DestinationAddrSlice() []byte {
	return h[16:20]
}

// PayloadLength returns payload length (total - header)
func (h IPv4Header) PayloadLength() uint16 {
	return h.TotalLength() - uint16(h.HeaderLength())
}

// Payload returns the payload (data after IP header)
func (h IPv4Header) Payload() []byte {
	headerLen := h.HeaderLength()
	if len(h) < headerLen {
		return nil
	}
	return h[headerLen:]
}

// CalculateChecksum calculates and returns the IPv4 header checksum
func (h IPv4Header) CalculateChecksum() uint16 {
	// Clear existing checksum
	h.SetChecksum(0)
	return Checksum(h[:h.HeaderLength()], 0)
}

// IPv6Header represents an IPv6 header
type IPv6Header []byte

// Version returns the IP version (should be 6)
func (h IPv6Header) Version() int {
	return int(h[0] >> 4)
}

// PayloadLength returns the payload length
func (h IPv6Header) PayloadLength() uint16 {
	return binary.BigEndian.Uint16(h[4:6])
}

// SetPayloadLength sets the payload length
func (h IPv6Header) SetPayloadLength(length uint16) {
	binary.BigEndian.PutUint16(h[4:6], length)
}

// NextHeader returns the next header protocol number
func (h IPv6Header) NextHeader() uint8 {
	return h[6]
}

// SourceAddr returns the source IP address
func (h IPv6Header) SourceAddr() netip.Addr {
	return netip.AddrFrom16([16]byte(h[8:24]))
}

// SetSourceAddr sets the source IP address
func (h IPv6Header) SetSourceAddr(addr netip.Addr) {
	copy(h[8:24], addr.AsSlice())
}

// DestinationAddr returns the destination IP address
func (h IPv6Header) DestinationAddr() netip.Addr {
	return netip.AddrFrom16([16]byte(h[24:40]))
}

// SetDestinationAddr sets the destination IP address
func (h IPv6Header) SetDestinationAddr(addr netip.Addr) {
	copy(h[24:40], addr.AsSlice())
}

// SourceAddrSlice returns source address as byte slice
func (h IPv6Header) SourceAddrSlice() []byte {
	return h[8:24]
}

// DestinationAddrSlice returns destination address as byte slice
func (h IPv6Header) DestinationAddrSlice() []byte {
	return h[24:40]
}

// Payload returns the payload (data after IPv6 header)
func (h IPv6Header) Payload() []byte {
	if len(h) < IPv6HeaderSize {
		return nil
	}
	return h[IPv6HeaderSize:]
}

// TCPHeader represents a TCP header
type TCPHeader []byte

// SourcePort returns the source port
func (h TCPHeader) SourcePort() uint16 {
	return binary.BigEndian.Uint16(h[0:2])
}

// SetSourcePort sets the source port
func (h TCPHeader) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(h[0:2], port)
}

// DestinationPort returns the destination port
func (h TCPHeader) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(h[2:4])
}

// SetDestinationPort sets the destination port
func (h TCPHeader) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(h[2:4], port)
}

// SequenceNumber returns the sequence number
func (h TCPHeader) SequenceNumber() uint32 {
	return binary.BigEndian.Uint32(h[4:8])
}

// AckNumber returns the acknowledgment number
func (h TCPHeader) AckNumber() uint32 {
	return binary.BigEndian.Uint32(h[8:12])
}

// DataOffset returns the data offset in bytes
func (h TCPHeader) DataOffset() int {
	return int(h[12]>>4) * 4
}

// Flags returns the TCP flags
func (h TCPHeader) Flags() uint8 {
	return h[13]
}

// Checksum returns the TCP checksum
func (h TCPHeader) Checksum() uint16 {
	return binary.BigEndian.Uint16(h[16:18])
}

// SetChecksum sets the TCP checksum
func (h TCPHeader) SetChecksum(checksum uint16) {
	binary.BigEndian.PutUint16(h[16:18], checksum)
}

// Payload returns the TCP payload
func (h TCPHeader) Payload() []byte {
	offset := h.DataOffset()
	if len(h) < offset {
		return nil
	}
	return h[offset:]
}

// CalculateChecksum calculates TCP checksum given pseudo-header checksum
func (h TCPHeader) CalculateChecksum(pseudoChecksum uint16) uint16 {
	return Checksum(h, pseudoChecksum)
}

// UDPHeader represents a UDP header
type UDPHeader []byte

// SourcePort returns the source port
func (h UDPHeader) SourcePort() uint16 {
	return binary.BigEndian.Uint16(h[0:2])
}

// SetSourcePort sets the source port
func (h UDPHeader) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(h[0:2], port)
}

// DestinationPort returns the destination port
func (h UDPHeader) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(h[2:4])
}

// SetDestinationPort sets the destination port
func (h UDPHeader) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(h[2:4], port)
}

// Length returns the UDP length (header + payload)
func (h UDPHeader) Length() uint16 {
	return binary.BigEndian.Uint16(h[4:6])
}

// SetLength sets the UDP length
func (h UDPHeader) SetLength(length uint16) {
	binary.BigEndian.PutUint16(h[4:6], length)
}

// Checksum returns the UDP checksum
func (h UDPHeader) Checksum() uint16 {
	return binary.BigEndian.Uint16(h[6:8])
}

// SetChecksum sets the UDP checksum
func (h UDPHeader) SetChecksum(checksum uint16) {
	binary.BigEndian.PutUint16(h[6:8], checksum)
}

// Payload returns the UDP payload
func (h UDPHeader) Payload() []byte {
	length := h.Length()
	if int(length) < UDPHeaderSize || len(h) < int(length) {
		return nil
	}
	return h[UDPHeaderSize:length]
}

// CalculateChecksum calculates UDP checksum given pseudo-header checksum
func (h UDPHeader) CalculateChecksum(pseudoChecksum uint16) uint16 {
	return Checksum(h, pseudoChecksum)
}

// IPVersion returns the IP version from a packet (4 or 6)
func IPVersion(packet []byte) int {
	if len(packet) == 0 {
		return 0
	}
	return int(packet[0] >> 4)
}
