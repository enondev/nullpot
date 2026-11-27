//go:build linux

package widenet

import (
	"fmt"
	"net"
	"syscall"
)

// applyOriginalDst applies SO_ORIGINAL_DST to the socket to recover the
// original destination of redirected traffic. Linux-only.
func applyOriginalDst(pc net.PacketConn) error {
	conn, ok := pc.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return fmt.Errorf("widenet: connection does not support SyscallConn")
	}

	rawConn, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("widenet: get raw conn: %w", err)
	}

	var errVal error
	err = rawConn.Control(func(fd uintptr) {
		errVal = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, 0x50 /* SO_ORIGINAL_DST */, 1)
	})
	if err != nil {
		return err
	}
	if errVal != nil {
		return fmt.Errorf("widenet: set SO_ORIGINAL_DST: %w", errVal)
	}
	return nil
}
