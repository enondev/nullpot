package ingest

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/enondev/nullpot/specs"
)

func TestReceiverHandleIngestSingleEvent(t *testing.T) {
	store := NewEventStore()
	events := make(chan specs.ThreatEvent, 10)
	recv := NewReceiver(events, store, specs.Product{Name: "test", UID: "test-uid"})

	event := specs.ThreatEvent{
		ClassUID:    2004,
		CategoryUID: 2,
		ActivityID:  1,
		Time:        time.Now().UTC(),
		Metadata: specs.Metadata{
			Version: "1.3.0",
			Product: specs.Product{Name: "sensor-1", UID: "s1"},
		},
		FindingInfo: specs.FindingInfo{
			UID:   "evt-test-1",
			Title: "test finding",
			Types: []string{"exploit_attempt"},
		},
	}
	data, _ := json.Marshal(event)

	req := httptest.NewRequest("POST", "/v1/ingest", strings.NewReader(string(data)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	recv.handleIngest(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}
	if store.Len() != 1 {
		t.Fatalf("expected 1 event in store, got %d", store.Len())
	}

	// Check event was pushed to channel
	select {
	case ev := <-events:
		if ev.FindingInfo.UID != "evt-test-1" {
			t.Fatalf("unexpected event UID: %s", ev.FindingInfo.UID)
		}
	default:
		t.Fatal("expected event on channel")
	}
}

func TestReceiverHandleIngestGzip(t *testing.T) {
	store := NewEventStore()
	events := make(chan specs.ThreatEvent, 10)
	recv := NewReceiver(events, store, specs.Product{Name: "test", UID: "test-uid"})

	event := specs.ThreatEvent{
		ClassUID:    2004,
		CategoryUID: 2,
		ActivityID:  1,
		Time:        time.Now().UTC(),
		Metadata: specs.Metadata{
			Version: "1.3.0",
			Product: specs.Product{Name: "sensor-1", UID: "s1"},
		},
		FindingInfo: specs.FindingInfo{
			UID:   "evt-test-gzip",
			Title: "gzip finding",
			Types: []string{"port_scan"},
		},
	}
	data, _ := json.Marshal(event)

	var buf strings.Builder
	gz := gzip.NewWriter(&buf)
	gz.Write(data)
	gz.Close()

	req := httptest.NewRequest("POST", "/v1/ingest", strings.NewReader(buf.String()))
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	recv.handleIngest(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}
	if store.Len() != 1 {
		t.Fatalf("expected 1 event in store, got %d", store.Len())
	}
}

func TestReceiverHandleIngestBatch(t *testing.T) {
	store := NewEventStore()
	events := make(chan specs.ThreatEvent, 10)
	recv := NewReceiver(events, store, specs.Product{Name: "test", UID: "test-uid"})

	batch := []specs.ThreatEvent{
		{
			ClassUID:    2004,
			CategoryUID: 2,
			ActivityID:  1,
			Time:        time.Now().UTC(),
			Metadata: specs.Metadata{
				Version: "1.3.0",
				Product: specs.Product{Name: "sensor-1", UID: "s1"},
			},
			FindingInfo: specs.FindingInfo{
				UID:   "evt-batch-1",
				Title: "batch 1",
				Types: []string{"exploit_attempt"},
			},
		},
		{
			ClassUID:    2004,
			CategoryUID: 2,
			ActivityID:  1,
			Time:        time.Now().UTC(),
			Metadata: specs.Metadata{
				Version: "1.3.0",
				Product: specs.Product{Name: "sensor-1", UID: "s1"},
			},
			FindingInfo: specs.FindingInfo{
				UID:   "evt-batch-2",
				Title: "batch 2",
				Types: []string{"port_scan"},
			},
		},
	}
	data, _ := json.Marshal(batch)

	req := httptest.NewRequest("POST", "/v1/ingest", strings.NewReader(string(data)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	recv.handleIngest(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", w.Code)
	}
	if store.Len() != 2 {
		t.Fatalf("expected 2 events in store, got %d", store.Len())
	}
}

func TestReceiverHandleIngestInvalid(t *testing.T) {
	store := NewEventStore()
	events := make(chan specs.ThreatEvent, 10)
	recv := NewReceiver(events, store, specs.Product{Name: "test", UID: "test-uid"})

	req := httptest.NewRequest("POST", "/v1/ingest", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	recv.handleIngest(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestReceiverHandleIngestWrongMethod(t *testing.T) {
	store := NewEventStore()
	events := make(chan specs.ThreatEvent, 10)
	recv := NewReceiver(events, store, specs.Product{Name: "test", UID: "test-uid"})

	req := httptest.NewRequest("GET", "/v1/ingest", nil)
	w := httptest.NewRecorder()

	recv.handleIngest(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestReceiverStartCancels(t *testing.T) {
	store := NewEventStore()
	events := make(chan specs.ThreatEvent, 10)
	recv := NewReceiver(events, store, specs.Product{Name: "test", UID: "test-uid"})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = recv.Start(ctx, ":0") }()
	cancel()
}

func TestEventStoreAddAllLen(t *testing.T) {
	s := NewEventStore()
	if s.Len() != 0 {
		t.Fatal("expected empty store")
	}

	ev1 := specs.ThreatEvent{FindingInfo: specs.FindingInfo{UID: "e1"}}
	ev2 := specs.ThreatEvent{FindingInfo: specs.FindingInfo{UID: "e2"}}
	s.Add(ev1)
	s.Add(ev2)

	if s.Len() != 2 {
		t.Fatalf("expected len 2, got %d", s.Len())
	}

	all := s.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 events, got %d", len(all))
	}

	// Modifying returned slice should not affect store
	all[0] = specs.ThreatEvent{}
	if s.All()[0].FindingInfo.UID != "e1" {
		t.Fatal("store was modified through returned slice")
	}
}
