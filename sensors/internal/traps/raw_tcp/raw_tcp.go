// Package raw_tcp implements stateful banner/payload traps (Redis :6379,
// Docker :2375).
package raw_tcp

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sync"

	"github.com/enondev/nullpot/specs"
)

// maxQuarantine caps the number of quarantined payloads to prevent memory
// exhaustion from attackers sending many unique payloads.
const maxQuarantine = 10000

// TrapModule is a stateful TCP trap that captures banners and payloads for
// Redis and Docker services.
type TrapModule struct {
	listen     string
	events     chan specs.ThreatEvent
	product    specs.Product
	server     *net.TCPListener
	quarantine map[string][]byte
	quarOrder  []string
	mu         sync.RWMutex
}

// New creates a raw TCP trap bound to listen.
func New(listen string, events chan specs.ThreatEvent, product specs.Product) (*TrapModule, error) {
	return &TrapModule{
		listen:     listen,
		events:     events,
		product:    product,
		quarantine: make(map[string][]byte),
		quarOrder:  make([]string, 0, maxQuarantine),
	}, nil
}

// Name returns the module identifier.
func (t *TrapModule) Name() string { return "raw_tcp" }

// Start runs the TCP listener until ctx is cancelled.
func (t *TrapModule) Start(ctx context.Context, _ chan<- specs.ThreatEvent) error {
	ln, err := net.Listen("tcp", t.listen)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go t.handleConn(conn)
	}
}

func (t *TrapModule) handleConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	// Service detection: read initial banner/probe.
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024), 65536)

	// Read first line as potential banner/command.
	if scanner.Scan() {
		line := scanner.Text()
		payload := []byte(line + "\n")
		t.quarantinePayload(remote, payload)
		t.emitEvent(remote, "banner", line)
	}

	// Continue reading payloads until ctx done or connection closes.
	for {
		if !scanner.Scan() {
			return
		}
		line := scanner.Text()
		payload := []byte(line + "\n")
		t.quarantinePayload(remote, payload)
		t.emitEvent(remote, "payload", line)
	}
}

func (t *TrapModule) quarantinePayload(_ string, payload []byte) {
	sum := sha256.Sum256(payload)
	key := hex.EncodeToString(sum[:])
	t.mu.Lock()
	if _, exists := t.quarantine[key]; !exists {
		if len(t.quarantine) >= maxQuarantine {
			oldest := t.quarOrder[0]
			t.quarOrder = t.quarOrder[1:]
			delete(t.quarantine, oldest)
		}
		t.quarantine[key] = payload
		t.quarOrder = append(t.quarOrder, key)
	}
	t.mu.Unlock()
}

func (t *TrapModule) emitEvent(remote, kind, content string) {
	ev := specs.ThreatEvent{
		ClassUID:    specs.ClassUIDNetworkActivity,
		CategoryUID: specs.CategoryUIDPotentialSecurityIssue,
		ActivityID:  specs.ActivityIDCreate,
		Metadata: specs.Metadata{
			Version: "1.3.0",
			Product: t.product,
		},
		SrcEndpoint: specs.Endpoint{IP: remote, Port: 0},
		FindingInfo: specs.FindingInfo{
			UID:   "evt_raw_tcp",
			Title: "Raw TCP trap hit",
			Types: []string{"exploit_attempt"},
		},
		Enrichment: specs.Enrichment{
			Module:         "raw_tcp",
			Fingerprint:    kind,
			PayloadPreview: truncate(content, 200),
		},
	}
	select {
	case t.events <- ev:
	default:
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
