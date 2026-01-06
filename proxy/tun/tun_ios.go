//go:build ios

package tun

import (
	"context"
	"runtime/debug"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// PacketIO interface for iOS NEPacketTunnelProvider integration
// Implemented by Swift/ObjC bridge and passed via SetPacketIO before starting Xray
type PacketIO interface {
	// ReadPacket reads a single packet from the TUN device
	// Returns: packet data, IP protocol (4 for IPv4, 6 for IPv6), error
	ReadPacket() ([]byte, int, error)

	// WritePacket writes a packet to the TUN device
	// protocol: 4 for IPv4, 6 for IPv6
	WritePacket(data []byte, protocol int) error

	// Close closes the packet flow
	Close() error
}

var (
	iosPacketIO PacketIO
	iosMutex    sync.Mutex
)

// SetPacketIO sets the PacketIO implementation from iOS side
// Must be called before starting Xray TUN inbound
func SetPacketIO(p PacketIO) {
	iosMutex.Lock()
	defer iosMutex.Unlock()
	iosPacketIO = p
	errors.LogInfo(context.Background(), "iOS PacketIO set")
}

// GetPacketIO returns the current PacketIO implementation
func GetPacketIO() PacketIO {
	iosMutex.Lock()
	defer iosMutex.Unlock()
	return iosPacketIO
}

// IOSTun implements Tun interface for iOS
type IOSTun struct {
	options    TunOptions
	packetIO   PacketIO
	bufferPool *sync.Pool
	closed     bool
	closeMutex sync.Mutex
}

// IOSTun implements Tun
var _ Tun = (*IOSTun)(nil)

func init() {
	// iOS NetworkExtension memory limit is ~15MB
	// Go runtime takes ~5MB, we need to be aggressive with GC

	// Run GC more frequently (default is 100)
	debug.SetGCPercent(10)

	// Set soft memory limit to 12MB to leave headroom
	debug.SetMemoryLimit(12 << 20)

	// Periodically return memory to OS
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			debug.FreeOSMemory()
		}
	}()
}

// NewTun creates a new iOS TUN handler
func NewTun(options TunOptions) (Tun, error) {
	iosMutex.Lock()
	p := iosPacketIO
	iosMutex.Unlock()

	if p == nil {
		return nil, errors.New("PacketIO not set, call SetPacketIO first from iOS")
	}

	mtu := options.MTU
	if mtu == 0 {
		mtu = 1500
	}

	t := &IOSTun{
		options:  options,
		packetIO: p,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				// Allocate buffer with MTU size
				return make([]byte, mtu)
			},
		},
	}

	errors.LogInfo(context.Background(), "iOS TUN created with MTU ", mtu)
	return t, nil
}

// Start implements Tun.Start
func (t *IOSTun) Start() error {
	errors.LogInfo(context.Background(), "iOS TUN started")
	return nil
}

// Close implements Tun.Close
func (t *IOSTun) Close() error {
	t.closeMutex.Lock()
	defer t.closeMutex.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	if t.packetIO != nil {
		return t.packetIO.Close()
	}
	return nil
}

// IsClosed returns whether the TUN is closed
func (t *IOSTun) IsClosed() bool {
	t.closeMutex.Lock()
	defer t.closeMutex.Unlock()
	return t.closed
}

// ReadPacket reads a packet from iOS PacketFlow
func (t *IOSTun) ReadPacket() ([]byte, int, error) {
	if t.IsClosed() {
		return nil, 0, errors.New("TUN closed")
	}
	return t.packetIO.ReadPacket()
}

// WritePacket writes a packet to iOS PacketFlow
func (t *IOSTun) WritePacket(data []byte, protocol int) error {
	if t.IsClosed() {
		return errors.New("TUN closed")
	}
	return t.packetIO.WritePacket(data, protocol)
}

// GetBuffer gets a buffer from pool
func (t *IOSTun) GetBuffer() []byte {
	return t.bufferPool.Get().([]byte)
}

// PutBuffer returns a buffer to pool
func (t *IOSTun) PutBuffer(buf []byte) {
	// Clear sensitive data before returning to pool
	for i := range buf {
		buf[i] = 0
	}
	t.bufferPool.Put(buf)
}

// Options returns TUN options
func (t *IOSTun) Options() TunOptions {
	return t.options
}
