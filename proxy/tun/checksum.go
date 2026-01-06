//go:build ios

package tun

import "encoding/binary"

// Checksum calculates the checksum (as defined in RFC 1071) of the bytes in the given byte slice.
// If initial is non-zero, it is folded into the checksum.
func Checksum(buf []byte, initial uint16) uint16 {
	sum := uint32(initial)

	// Process 2 bytes at a time
	for len(buf) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(buf))
		buf = buf[2:]
	}

	// Handle odd byte
	if len(buf) == 1 {
		sum += uint32(buf[0]) << 8
	}

	// Fold 32-bit sum to 16 bits
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return uint16(sum)
}

// PseudoHeaderChecksum calculates the pseudo-header checksum for TCP/UDP
// over IPv4 or IPv6. The checksum includes src/dst addresses, protocol, and length.
func PseudoHeaderChecksum(protocol uint8, srcAddr, dstAddr []byte, totalLen uint16) uint16 {
	sum := uint32(0)

	// Sum source address
	for i := 0; i < len(srcAddr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(srcAddr[i:]))
	}

	// Sum destination address
	for i := 0; i < len(dstAddr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(dstAddr[i:]))
	}

	// Add protocol and length
	sum += uint32(protocol)
	sum += uint32(totalLen)

	// Fold to 16 bits
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	return uint16(sum)
}
