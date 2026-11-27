//go:build !linux

package widenet

import (
	"fmt"
	"net"
)

// applyOriginalDst is a no-op on non-Linux platforms.
func applyOriginalDst(pc net.PacketConn) error {
	return fmt.Errorf("widenet: SO_ORIGINAL_DST is only supported on Linux; running on %s", pc.LocalAddr().Network())
}
