# ADR-0016: Widenet Listener SO_ORIGINAL_DST

## Status
Accepted

## Context
The Widenet listener uses SO_ORIGINAL_DST to recover the original destination
of redirected trap traffic. Previously, the SO_ORIGINAL_DST syscall application
was documented as TODO pending platform-specific build tags due to
syscall.Handle typing differences across platforms.

## Decision
- `widenet_linux.go` applies SO_ORIGINAL_DST (0x50 on SOL_IP) via
  `SyscallConn()` on Linux, recovering the original destination of redirected
  packets for accurate trap attribution.
- `widenet_other.go` returns an error on non-Linux platforms, as
  SO_ORIGINAL_DST is Linux-specific.
- The `Listener.Start()` method calls `applyOriginalDst()` after binding the
  socket and before reading packets.
- If SO_ORIGINAL_DST fails, `Start()` returns an error rather than silently
  proceeding without destination recovery.

## Consequences
- On Linux, captured traffic includes the original destination IP/port,
  enabling accurate attribution of redirected trap traffic.
- On non-Linux platforms, the listener fails to start with a clear error
  rather than silently operating without destination recovery.
- Platform-specific build tags keep the code cross-platform compilable.
