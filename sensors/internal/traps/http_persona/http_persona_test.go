package http_persona

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/enondev/nullpot/sensors/internal/core"
	"github.com/enondev/nullpot/specs"
)

func TestTrapModuleName(t *testing.T) {
	tm := &TrapModule{}
	if tm.Name() != "http_persona" {
		t.Fatalf("unexpected name: %s", tm.Name())
	}
}

func TestMakeHandlerInjectsCanary(t *testing.T) {
	loader := core.NewLoader()
	dir := t.TempDir()
	path := filepath.Join(dir, "persona.yaml")
	if err := os.WriteFile(path, []byte(`id: test-persona
name: Test
banner: Test Banner
canary_token_inject: true
routes:
  - path: /test
    method: GET
    response:
      status: 200
      body: ok
    capture:
      body: true
      headers: true
`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := loader.LoadFile(path); err != nil {
		t.Fatalf("load: %v", err)
	}

	canary := core.NewGenerator()
	events := make(chan specs.ThreatEvent, 10)
	tm := New(loader, canary, ":0", events, specs.Product{Name: "x", UID: "y"})

	spec := loader.Get("test-persona")
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "203.0.113.45:54321"
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()

	tm.makeHandler(spec, spec.Routes[0])(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	tokenHeader := w.Header().Get("X-Canary-Token")
	if tokenHeader == "" {
		t.Fatal("expected X-Canary-Token header")
	}

	valueHeader := w.Header().Get("X-Canary-Value")
	if valueHeader == "" {
		t.Fatal("expected X-Canary-Value header (actual canary secret)")
	}

	if !canary.Validate(strings.TrimPrefix(tokenHeader, "cnry_")) {
		t.Fatal("token not registered in generator")
	}

	select {
	case ev := <-events:
		if ev.Enrichment.Module != "http_persona" || ev.Enrichment.PersonaID != "test-persona" {
			t.Fatalf("unexpected enrichment: %+v", ev.Enrichment)
		}
		if ev.Enrichment.Fingerprint != "test-agent" {
			t.Fatalf("unexpected fingerprint: %s", ev.Enrichment.Fingerprint)
		}
		if ev.SrcEndpoint.IP != "203.0.113.45" {
			t.Fatalf("unexpected src IP: %s", ev.SrcEndpoint.IP)
		}
	default:
		t.Fatal("expected event on channel")
	}
}

func TestMakeHandlerHashesPayload(t *testing.T) {
	loader := core.NewLoader()
	dir := t.TempDir()
	path := filepath.Join(dir, "persona.yaml")
	if err := os.WriteFile(path, []byte(`id: test
banner: x
canary_token_inject: false
routes:
  - path: /post
    method: POST
    response:
      status: 200
      body: ok
    capture:
      body: true
      headers: true
`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := loader.LoadFile(path); err != nil {
		t.Fatalf("load: %v", err)
	}

	canary := core.NewGenerator()
	events := make(chan specs.ThreatEvent, 10)
	tm := New(loader, canary, ":0", events, specs.Product{Name: "x", UID: "y"})

	spec := loader.Get("test")
	body := []byte(`{"prompt":"malicious"}`)
	req := httptest.NewRequest("POST", "/post", strings.NewReader(string(body)))
	req.RemoteAddr = "198.51.100.2:12345"
	w := httptest.NewRecorder()

	tm.makeHandler(spec, spec.Routes[0])(w, req)

	select {
	case ev := <-events:
		sum := sha256.Sum256(body)
		expectedSHA := hex.EncodeToString(sum[:])
		if ev.Enrichment.PayloadSHA256 != expectedSHA {
			t.Fatalf("expected SHA %s, got %s", expectedSHA, ev.Enrichment.PayloadSHA256)
		}
		if ev.Enrichment.PayloadPreview != string(body) {
			t.Fatalf("unexpected preview: %s", ev.Enrichment.PayloadPreview)
		}
	default:
		t.Fatal("expected event on channel")
	}
}

func TestMakeHandlerDropOldestOnFullChannel(t *testing.T) {
	loader := core.NewLoader()
	dir := t.TempDir()
	path := filepath.Join(dir, "persona.yaml")
	if err := os.WriteFile(path, []byte(`id: test
banner: x
canary_token_inject: false
routes:
  - path: /test
    method: GET
    response:
      status: 200
      body: ok
    capture:
      body: false
      headers: false
`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := loader.LoadFile(path); err != nil {
		t.Fatalf("load: %v", err)
	}

	canary := core.NewGenerator()
	events := make(chan specs.ThreatEvent, 1)
	tm := New(loader, canary, ":0", events, specs.Product{Name: "x", UID: "y"})

	events <- specs.ThreatEvent{}

	spec := loader.Get("test")
	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "203.0.113.45:54321"
	w := httptest.NewRecorder()

	tm.makeHandler(spec, spec.Routes[0])(w, req)
}

func TestStartCancels(t *testing.T) {
	loader := core.NewLoader()
	canary := core.NewGenerator()
	events := make(chan specs.ThreatEvent, 10)
	tm := New(loader, canary, ":0", events, specs.Product{Name: "x", UID: "y"})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = tm.Start(ctx, events) }()
	cancel()
}

var _ = io.Discard
var _ = http.StatusOK
