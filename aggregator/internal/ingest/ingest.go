// Package ingest implements the OpenAPI sensor webhook receiver, Canary
// callback listener, and OSINT/BGP pullers.
package ingest

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/enondev/nullpot/specs"
)

// Receiver ingests ThreatEvents from sensors via gzip JSON POST /v1/ingest.
type Receiver struct {
	events  chan<- specs.ThreatEvent
	store   *EventStore
	product specs.Product
	server  *http.Server
	mu      sync.Mutex
}

// EventStore holds received events in memory for correlation.
type EventStore struct {
	mu     sync.RWMutex
	events []specs.ThreatEvent
}

// NewEventStore creates an empty event store.
func NewEventStore() *EventStore {
	return &EventStore{events: make([]specs.ThreatEvent, 0)}
}

// Add appends an event to the store.
func (s *EventStore) Add(ev specs.ThreatEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

// All returns a copy of all stored events.
func (s *EventStore) All() []specs.ThreatEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]specs.ThreatEvent, len(s.events))
	copy(out, s.events)
	return out
}

// Len returns the number of stored events.
func (s *EventStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

// NewReceiver creates an ingest receiver.
func NewReceiver(events chan<- specs.ThreatEvent, store *EventStore, product specs.Product) *Receiver {
	return &Receiver{
		events:  events,
		store:   store,
		product: product,
	}
}

// Name returns the receiver identifier.
func (r *Receiver) Name() string { return "ingest" }

// Start runs the HTTP ingest server until ctx is cancelled.
func (r *Receiver) Start(ctx context.Context, listenAddr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/ingest", r.handleIngest)

	r.server = &http.Server{
		Addr:    listenAddr,
		Handler: mux,
	}

	go func() {
		if err := r.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// server shutting down
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return r.server.Shutdown(shutdownCtx)
}

func (r *Receiver) handleIngest(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Decompress gzip body if needed.
	var body io.Reader = req.Body
	if req.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(req.Body)
		if err != nil {
			http.Error(w, "invalid gzip", http.StatusBadRequest)
			return
		}
		defer gz.Close()
		body = gz
	}

	data, err := io.ReadAll(body)
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}

	// Try single event first, then batch.
	var events []specs.ThreatEvent
	var single specs.ThreatEvent
	if err := json.Unmarshal(data, &single); err == nil && single.ClassUID != 0 {
		events = []specs.ThreatEvent{single}
	} else {
		if err := json.Unmarshal(data, &events); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
	}

	for i := range events {
		ev := &events[i]
		ev.Time = time.Now().UTC()
		if ev.Metadata.Product.Name == "" {
			ev.Metadata.Product = r.product
		}
		if err := ev.Validate(); err != nil {
			http.Error(w, "invalid event: "+err.Error(), http.StatusBadRequest)
			return
		}
		r.store.Add(*ev)
		// Push to channel non-blocking for downstream correlation.
		select {
		case r.events <- *ev:
		default:
		}
	}

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}
