package raw_tcp

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/enondev/nullpot/specs"
)

func TestTrapModuleName(t *testing.T) {
	tm := &TrapModule{}
	if tm.Name() != "raw_tcp" {
		t.Fatalf("unexpected name: %s", tm.Name())
	}
}

func TestQuarantinePayload(t *testing.T) {
	tm := &TrapModule{quarantine: make(map[string][]byte)}
	payload := []byte("redis config rewrite")
	tm.quarantinePayload("203.0.113.45", payload)

	sum := sha256.Sum256(payload)
	key := hex.EncodeToString(sum[:])
	if _, ok := tm.quarantine[key]; !ok {
		t.Fatal("expected payload in quarantine")
	}
	if string(tm.quarantine[key]) != "redis config rewrite" {
		t.Fatal("unexpected quarantined payload")
	}
}

func TestEmitEventFields(t *testing.T) {
	tm := &TrapModule{
		events:  make(chan specs.ThreatEvent, 10),
		product: specs.Product{Name: "x", UID: "y"},
	}
	tm.emitEvent("203.0.113.45", "banner", "redis_version:7.0.0")

	select {
	case ev := <-tm.events:
		if ev.Enrichment.Module != "raw_tcp" {
			t.Fatalf("unexpected module: %s", ev.Enrichment.Module)
		}
		if ev.Enrichment.Fingerprint != "banner" {
			t.Fatalf("unexpected fingerprint: %s", ev.Enrichment.Fingerprint)
		}
		if !strings.Contains(ev.Enrichment.PayloadPreview, "redis_version") {
			t.Fatalf("expected banner in preview: %s", ev.Enrichment.PayloadPreview)
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
	if len(truncate("this is a long string", 10)) != 10 {
		t.Fatal("truncate should respect limit")
	}
}
