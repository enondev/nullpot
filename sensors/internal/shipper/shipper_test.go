package shipper

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/enondev/nullpot/specs"
)

func TestShipperConfigDefaults(t *testing.T) {
	s := New(Config{AggregatorURL: "http://localhost/v1/ingest"})
	if s.cfg.BufferSize != 1024 {
		t.Fatalf("expected default buffer 1024, got %d", s.cfg.BufferSize)
	}
	if s.cfg.BatchSize != 100 {
		t.Fatalf("expected default batch 100, got %d", s.cfg.BatchSize)
	}
	if s.cfg.BatchTimeout != 5*time.Second {
		t.Fatalf("expected default timeout 5s, got %v", s.cfg.BatchTimeout)
	}
	if s.cfg.HTTPTimeout != 10*time.Second {
		t.Fatalf("expected default http timeout 10s, got %v", s.cfg.HTTPTimeout)
	}
}

func TestShipperPushNonBlocking(t *testing.T) {
	s := New(Config{
		AggregatorURL: "http://localhost/v1/ingest",
		BufferSize:    1,
		BatchSize:     10,
		BatchTimeout:  time.Hour,
	})

	// Fill the channel
	s.Push(specs.ThreatEvent{})

	// Should not block when full
	s.Push(specs.ThreatEvent{})
}

func TestShipperSendBatchGzip(t *testing.T) {
	var received []specs.ThreatEvent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Content-Encoding") != "gzip" {
			t.Fatalf("expected gzip encoding, got %s", r.Header.Get("Content-Encoding"))
		}
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Fatalf("gzip reader: %v", err)
		}
		defer gz.Close()
		body, err := io.ReadAll(gz)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if err := json.Unmarshal(body, &received); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	s := New(Config{
		AggregatorURL: server.URL + "/v1/ingest",
		BufferSize:    10,
		BatchSize:     2,
		BatchTimeout:  time.Hour,
		HTTPTimeout:   5 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Start(ctx)

	s.Push(specs.ThreatEvent{FindingInfo: specs.FindingInfo{UID: "evt-1"}})
	s.Push(specs.ThreatEvent{FindingInfo: specs.FindingInfo{UID: "evt-2"}})

	// Wait for batch to flush
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(received) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if len(received) != 2 {
		t.Fatalf("expected 2 events, got %d", len(received))
	}
	if received[0].FindingInfo.UID != "evt-1" || received[1].FindingInfo.UID != "evt-2" {
		t.Fatalf("unexpected events: %+v", received)
	}
}

func TestShipperFlushOnTimeout(t *testing.T) {
	var received []specs.ThreatEvent
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gz, _ := gzip.NewReader(r.Body)
		defer gz.Close()
		body, _ := io.ReadAll(gz)
		json.Unmarshal(body, &received)
		w.WriteHeader(200)
	}))
	defer server.Close()

	s := New(Config{
		AggregatorURL: server.URL + "/v1/ingest",
		BufferSize:    10,
		BatchSize:     100,
		BatchTimeout:  50 * time.Millisecond,
		HTTPTimeout:   5 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Start(ctx)

	s.Push(specs.ThreatEvent{FindingInfo: specs.FindingInfo{UID: "evt-timeout"}})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(received) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if len(received) != 1 {
		t.Fatalf("expected 1 event on timeout flush, got %d", len(received))
	}
}
