// Package ingest implements the OpenAPI sensor webhook receiver, Canary
// callback listener, and OSINT/BGP pullers.
package ingest

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/enondev/nullpot/specs"
)

// maxEventsDefault is the default maximum number of events stored in memory.
const maxEventsDefault = 1_000_000

// rateLimiter is a simple token bucket per source IP.
type rateLimiter struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	rate   float64 // tokens per second
	burst  float64
}

func newRateLimiter(rate, burst float64) *rateLimiter {
	return &rateLimiter{
		tokens: burst,
		last:   time.Now(),
		rate:   rate,
		burst:  burst,
	}
}

func (rl *rateLimiter) allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(rl.last).Seconds()
	rl.last = now
	rl.tokens += elapsed * rl.rate
	if rl.tokens > rl.burst {
		rl.tokens = rl.burst
	}
	if rl.tokens < 1.0 {
		return false
	}
	rl.tokens--
	return true
}

// Receiver ingests ThreatEvents from sensors via gzip JSON POST /v1/ingest.
type Receiver struct {
	events  chan<- specs.ThreatEvent
	store   *EventStore
	product specs.Product
	server  *http.Server
	mu      sync.Mutex

	rateLimiters map[string]*rateLimiter
	rlMu         sync.Mutex
}

// EventStore holds received events in memory for correlation.
type EventStore struct {
	mu        sync.RWMutex
	events    []specs.ThreatEvent
	maxEvents int
}

// NewEventStore creates an empty event store with the given max capacity.
func NewEventStore() *EventStore {
	return &EventStore{
		events:    make([]specs.ThreatEvent, 0),
		maxEvents: maxEventsDefault,
	}
}

// Add appends an event to the store, evicting oldest events (FIFO) when over capacity.
func (s *EventStore) Add(ev specs.ThreatEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
	if len(s.events) > s.maxEvents {
		overflow := len(s.events) - s.maxEvents
		s.events = s.events[overflow:]
	}
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

// MaxEvents returns the configured maximum event capacity.
func (s *EventStore) MaxEvents() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.maxEvents
}

// NewReceiver creates an ingest receiver.
func NewReceiver(events chan<- specs.ThreatEvent, store *EventStore, product specs.Product) *Receiver {
	return &Receiver{
		events:       events,
		store:        store,
		product:      product,
		rateLimiters: make(map[string]*rateLimiter),
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

func (r *Receiver) allowRate(ip string) bool {
	r.rlMu.Lock()
	defer r.rlMu.Unlock()
	rl, ok := r.rateLimiters[ip]
	if !ok {
		rl = newRateLimiter(10, 20) // 10 req/s, burst 20
		r.rateLimiters[ip] = rl
	}
	return rl.allow()
}

func srcIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func (r *Receiver) handleIngest(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Per-IP rate limiting.
	ip := srcIP(req.RemoteAddr)
	if !r.allowRate(ip) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
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
