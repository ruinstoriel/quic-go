package quic

import (
	"log"
	"net"
	"syscall"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

// OOBCapablePacketConn is a connection that allows the reading of ECN bits from the IP header.
// If the PacketConn passed to Dial or Listen satisfies this interface, quic-go will use it.
// In this case, ReadMsgUDP() will be used instead of ReadFrom() to read packets.
type OOBCapablePacketConn interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
}

type Obfuscator interface {
	// Obfuscate obfuscates the packet and returns the obfuscated packet.
	// To fully utilize UDP optimizations, the obfuscated packet can be returned
	// as multiple slices (scatter-gather) when scat == true. It will be sent as
	// a single packet. It must also return a function for freeing the slices.
	// Do NOT alter the original data - always make a copy.
	Obfuscate(data []byte, scat bool) ([][]byte, func())

	// Deobfuscate deobfuscates the packet.
	// The operation should be done in-place, and the deobfuscated packet should
	// never be larger than the obfuscated one.
	Deobfuscate([]byte) int
}

var _ OOBCapablePacketConn = &net.UDPConn{}

func wrapConn(pc net.PacketConn) (rawConn, error) {
	conn, ok := pc.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if ok {
		rawConn, err := conn.SyscallConn()
		if err != nil {
			return nil, err
		}

		if _, ok := pc.LocalAddr().(*net.UDPAddr); ok {
			// Only set DF on sockets that we expect to be able to handle that configuration.
			err = setDF(rawConn)
			if err != nil {
				return nil, err
			}
		}
	}
	obfs, ok := pc.(Obfuscator)
	if ok {
		log.Println("Using obfuscator")
	}
	c, ok := pc.(OOBCapablePacketConn)
	if !ok {
		utils.DefaultLogger.Infof("PacketConn is not a net.UDPConn. Disabling optimizations possible on UDP connections.")
		return &basicConn{PacketConn: pc, obfs: obfs}, nil
	}
	return newConn(c, obfs)
}

// The basicConn is the most trivial implementation of a connection.
// It reads a single packet from the underlying net.PacketConn.
// It is used when
// * the net.PacketConn is not a OOBCapablePacketConn, and
// * when the OS doesn't support OOB.
type basicConn struct {
	net.PacketConn

	obfs Obfuscator
}

var _ rawConn = &basicConn{}

func (c *basicConn) ReadPacket() (*receivedPacket, error) {
	buffer := getPacketBuffer()
	// The packet size should not exceed protocol.MaxPacketBufferSize bytes
	// If it does, we only read a truncated packet, which will then end up undecryptable
	buffer.Data = buffer.Data[:protocol.MaxPacketBufferSize]
	n, addr, err := c.PacketConn.ReadFrom(buffer.Data)
	if err != nil {
		return nil, err
	}
	if c.obfs != nil {
		n = c.obfs.Deobfuscate(buffer.Data[:n])
	}
	return &receivedPacket{
		remoteAddr: addr,
		rcvTime:    time.Now(),
		data:       buffer.Data[:n],
		buffer:     buffer,
	}, nil
}

func (c *basicConn) WritePacket(b []byte, addr net.Addr, _ []byte) (n int, err error) {
	if c.obfs != nil {
		bb, free := c.obfs.Obfuscate(b, false)
		defer free()
		b = bb[0]
	}
	return c.PacketConn.WriteTo(b, addr)
}

func (c *basicConn) WritePackets(packets [][]byte, addr net.Addr, _ []byte) (int, error) {
	for i, p := range packets {
		if c.obfs != nil {
			bb, free := c.obfs.Obfuscate(p, false)
			defer free()
			p = bb[0]
		}
		if _, err := c.PacketConn.WriteTo(p, addr); err != nil {
			return i, err
		}
	}
	return len(packets), nil
}

func (c *basicConn) newSendConn() rawSendConn {
	return c
}
