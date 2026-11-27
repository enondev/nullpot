package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/enondev/nullpot/sensors/internal/shipper"
	"github.com/enondev/nullpot/specs"
)

// fakeAggregator captures events POSTed to /v1/ingest.
type fakeAggregator struct {
	mu      sync.Mutex
	events  []specs.ThreatEvent
	lastReq *http.Request
}

func (f *fakeAggregator) handleIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var body io.Reader = r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		defer gz.Close()
		body = gz
	}

	data, err := io.ReadAll(body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var events []specs.ThreatEvent
	if err := json.Unmarshal(data, &events); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, events...)
	f.lastReq = r

	w.WriteHeader(http.StatusAccepted)
}

func makeSensorEvent(module, ip string) specs.ThreatEvent {
	return specs.ThreatEvent{
		ClassUID:    specs.ClassUIDNetworkActivity,
		CategoryUID: specs.CategoryUIDPotentialSecurityIssue,
		ActivityID:  specs.ActivityIDCreate,
		Time:        time.Now().UTC(),
		Metadata: specs.Metadata{
			Version: "1.3.0",
			Product: specs.Product{Name: "sensor", UID: "s1", Region: "local"},
		},
		SrcEndpoint: specs.Endpoint{IP: ip, Port: 12345},
		FindingInfo: specs.FindingInfo{
			UID:   "evt-sensor-" + ip,
			Title: "sensor test finding",
			Types: []string{"port_scan"},
		},
		Enrichment: specs.Enrichment{
			Module:         module,
			PayloadPreview: "test payload",
			PayloadSHA256:  "abc123",
		},
	}
}

func TestSensorToAggregatorPipeline(t *testing.T) {
	fake := &fakeAggregator{}
	srv := httptest.NewServer(http.HandlerFunc(fake.handleIngest))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sh := shipper.New(shipper.Config{
		AggregatorURL: srv.URL + "/v1/ingest",
		BufferSize:    64,
		BatchSize:     10,
		BatchTimeout:  50 * time.Millisecond,
		HTTPTimeout:   5 * time.Second,
	})

	go sh.Start(ctx)

	// Push widenet sweep + http_persona hit for same IP.
	ev1 := makeSensorEvent("widenet", "203.0.113.45")
	ev2 := makeSensorEvent("http_persona", "203.0.113.45")
	sh.Push(ev1)
	sh.Push(ev2)

	// Wait for events to be received by fake aggregator.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		fake.mu.Lock()
		n := len(fake.events)
		fake.mu.Unlock()
		if n >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.events) < 2 {
		t.Fatalf("expected at least 2 events, got %d", len(fake.events))
	}

	// Verify event modules.
	modules := map[string]bool{}
	for _, ev := range fake.events {
		modules[ev.Enrichment.Module] = true
	}
	if !modules["widenet"] {
		t.Error("expected widenet event")
	}
	if !modules["http_persona"] {
		t.Error("expected http_persona event")
	}
}
