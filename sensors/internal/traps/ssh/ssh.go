// Package ssh implements the modular SSH tarpit and command/dropper trap.
// Captured commands/payloads are hashed (SHA-256) and quarantined, never
// executed.
package ssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sync"

	"github.com/enondev/nullpot/specs"
	"golang.org/x/crypto/ssh"
)

// maxQuarantine caps the number of quarantined payloads to prevent memory
// exhaustion from attackers sending many unique payloads.
const maxQuarantine = 10000

// TrapModule is an SSH tarpit that logs authentication attempts, captures
// commands and dropped payloads, and emits OCSF Detection Finding events.
type TrapModule struct {
	banner     string
	hostKey    ssh.Signer
	events     chan specs.ThreatEvent
	listen     string
	product    specs.Product
	quarantine map[string][]byte
	quarOrder  []string // insertion order for LRU eviction
	mu         sync.RWMutex
}

// New creates an SSH trap bound to listen.
func New(listen string, events chan specs.ThreatEvent, product specs.Product) (*TrapModule, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, err
	}
	return &TrapModule{
		banner:     "SSH-2.0-nullpot_tarpit",
		hostKey:    signer,
		events:     events,
		listen:     listen,
		product:    product,
		quarantine: make(map[string][]byte),
		quarOrder:  make([]string, 0, maxQuarantine),
	}, nil
}

// Name returns the module identifier.
func (t *TrapModule) Name() string { return "ssh" }

// Start runs the SSH server until ctx is cancelled.
func (t *TrapModule) Start(ctx context.Context, _ chan<- specs.ThreatEvent) error {
	config := &ssh.ServerConfig{
		ServerVersion: t.banner,
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			_ = pass
			go t.emitEvent(c.User(), c.RemoteAddr().String(), "password_auth", "")
			return nil, nil
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			go t.emitEvent(c.User(), c.RemoteAddr().String(), "pubkey_auth", "")
			return nil, nil
		},
	}
	config.AddHostKey(t.hostKey)

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
		go t.handleConn(conn, config)
	}
}

func (t *TrapModule) handleConn(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "not a session")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go t.handleSession(channel, requests, sshConn.User(), sshConn.RemoteAddr().String())
	}
}

func (t *TrapModule) handleSession(channel ssh.Channel, requests <-chan *ssh.Request, user, remote string) {
	defer channel.Close()

	// Capture stdin data written to the channel (this is where command
	// payloads actually arrive; "stdin" is not a channel request type).
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := channel.Read(buf)
			if n > 0 {
				t.quarantinePayload(remote, buf[:n])
				t.emitEvent(user, remote, "command", string(buf[:n]))
			}
			if err != nil {
				return
			}
		}
	}()

	for req := range requests {
		switch req.Type {
		case "shell", "exec", "pty-req":
			req.Reply(true, nil)
		default:
			req.Reply(false, nil)
		}
	}
}

func (t *TrapModule) quarantinePayload(_ string, payload []byte) {
	sum := sha256.Sum256(payload)
	key := hex.EncodeToString(sum[:])
	t.mu.Lock()
	if _, exists := t.quarantine[key]; !exists {
		if len(t.quarantine) >= maxQuarantine {
			// Evict oldest entry (LRU).
			oldest := t.quarOrder[0]
			t.quarOrder = t.quarOrder[1:]
			delete(t.quarantine, oldest)
		}
		t.quarantine[key] = payload
		t.quarOrder = append(t.quarOrder, key)
	}
	t.mu.Unlock()
}

func (t *TrapModule) emitEvent(user, remote, authType, command string) {
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
			UID:   "evt_ssh",
			Title: "SSH tarpit hit",
			Types: []string{"exploit_attempt"},
		},
		Enrichment: specs.Enrichment{
			Module:         "ssh",
			Fingerprint:    user + ":" + authType,
			PayloadPreview: truncate(command, 200),
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
