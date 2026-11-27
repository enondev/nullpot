// Package widenet implements the all-port TCP/UDP listener using Linux
// SO_ORIGINAL_DST to capture the original destination of redirected traffic.
package widenet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/enondev/nullpot/specs"
)

// Listener captures all-port TCP/UDP trap traffic via SO_ORIGINAL_DST.
type Listener struct {
	network string
	address string
	conn    net.PacketConn
	events  chan<- specs.ThreatEvent
	stopped bool
	stopMu  sync.Mutex
}

// Name returns the module identifier.
func (l *Listener) Name() string { return "widenet" }

// NewListener creates a Widenet listener bound to address on the given
// network (tcp or udp).
func NewListener(network, address string, events chan<- specs.ThreatEvent) (*Listener, error) {
	if network != "tcp" && network != "udp" {
		return nil, fmt.Errorf("unsupported network: %q", network)
	}
	return &Listener{
		network: network,
		address: address,
		events:  events,
	}, nil
}

// Start binds the socket and begins reading packets. It blocks until ctx is
// cancelled. The events channel is provided via the TrapModule interface but
// already stored on the Listener at construction time.
func (l *Listener) Start(ctx context.Context, _ chan<- specs.ThreatEvent) error {
	pc, err := net.ListenPacket(l.network, l.address)
	if err != nil {
		return fmt.Errorf("widenet: listen %s %s: %w", l.network, l.address, err)
	}
	defer pc.Close()

	if err := applyOriginalDst(pc); err != nil {
		log.Printf("widenet: SO_ORIGINAL_DST not available: %v", err)
	}

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		ev := l.eventFromPacket(buf[:n], addr)
		if ev == nil {
			continue
		}
		select {
		case l.events <- *ev:
		case <-ctx.Done():
			return nil
		}
	}
}

// Stop halts the listener.
func (l *Listener) Stop() error {
	l.stopMu.Lock()
	defer l.stopMu.Unlock()
	if l.stopped {
		return nil
	}
	l.stopped = true
	if l.conn != nil {
		return l.conn.Close()
	}
	return nil
}

func (l *Listener) eventFromPacket(payload []byte, addr net.Addr) *specs.ThreatEvent {
	ip, port := hostPort(addr)
	if ip == "" {
		return nil
	}
	sum := sha256.Sum256(payload)
	payloadSHA := hex.EncodeToString(sum[:])
	return &specs.ThreatEvent{
		ClassUID:    specs.ClassUIDNetworkActivity,
		CategoryUID: specs.CategoryUIDPotentialSecurityIssue,
		ActivityID:  specs.ActivityIDCreate,
		Metadata: specs.Metadata{
			Version: "1.3.0",
			Product: specs.Product{
				Name:   "EdgeTrapSensor",
				UID:    "widenet",
				Region: "",
			},
		},
		SrcEndpoint: specs.Endpoint{IP: ip, Port: port},
		FindingInfo: specs.FindingInfo{
			UID:   "evt_widenet",
			Title: "Widenet port trap hit",
			Types: []string{"port_scan"},
		},
		Enrichment: specs.Enrichment{
			Module:         "widenet",
			PayloadPreview: truncate(string(payload), 200),
			PayloadSHA256:  payloadSHA,
		},
	}
}

func hostPort(addr net.Addr) (string, uint16) {
	switch a := addr.(type) {
	case *net.UDPAddr:
		if a.IP == nil {
			return "", 0
		}
		return a.IP.String(), uint16(a.Port)
	case *net.TCPAddr:
		if a.IP == nil {
			return "", 0
		}
		return a.IP.String(), uint16(a.Port)
	}
	return "", 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
