//go:build !darwin && !linux && !freebsd && !windows

package quic

import "net"

func newConn(c net.PacketConn, obfs Obfuscator) (rawConn, error) {
	return &basicConn{PacketConn: c, obfs: obfs}, nil
}

func inspectReadBuffer(interface{}) (int, error) {
	return 0, nil
}

func inspectWriteBuffer(interface{}) (int, error) {
	return 0, nil
}

func (i *packetInfo) OOB() []byte { return nil }
