// Package shipper implements the non-blocking buffered channel HTTP/batch
// exporter for sensor telemetry.
package shipper

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/enondev/nullpot/specs"
)

// Config for the shipper.
type Config struct {
	AggregatorURL string        // e.g. https://aggregator.nullpot.internal/v1/ingest
	BufferSize    int           // bounded channel capacity
	BatchSize     int           // max events per batch
	BatchTimeout  time.Duration // max wait before flushing partial batch
	HTTPTimeout   time.Duration // per-request timeout
}

// Shipper exports ThreatEvents to the aggregator via gzip JSON.
type Shipper struct {
	cfg     Config
	ch      chan specs.ThreatEvent
	client  *http.Client
	wg      sync.WaitGroup
	stopCh  chan struct{}
	stopped bool
	stopMu  sync.Mutex
}

// New creates a shipper with the given config.
func New(cfg Config) *Shipper {
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 1024
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.BatchTimeout <= 0 {
		cfg.BatchTimeout = 5 * time.Second
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 10 * time.Second
	}
	s := &Shipper{
		cfg:    cfg,
		ch:     make(chan specs.ThreatEvent, cfg.BufferSize),
		client: &http.Client{Timeout: cfg.HTTPTimeout},
		stopCh: make(chan struct{}),
	}
	return s
}

// Push sends an event to the shipper. Non-blocking: drops oldest on overflow.
func (s *Shipper) Push(ev specs.ThreatEvent) {
	select {
	case s.ch <- ev:
	default:
		// Drop-oldest overflow protection.
		select {
		case <-s.ch:
		default:
		}
		select {
		case s.ch <- ev:
		default:
		}
	}
}

// Start runs the batch flush loop until ctx is cancelled.
func (s *Shipper) Start(ctx context.Context) error {
	s.wg.Add(1)
	defer s.wg.Done()

	ticker := time.NewTicker(s.cfg.BatchTimeout)
	defer ticker.Stop()

	var batch []specs.ThreatEvent

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		return s.sendBatch(batch)
	}

	for {
		select {
		case <-ctx.Done():
			return flush()
		case <-s.stopCh:
			return flush()
		case ev := <-s.ch:
			batch = append(batch, ev)
			if len(batch) >= s.cfg.BatchSize {
				if err := flushBatch(&batch, flush); err != nil {
					return err
				}
			}
		case <-ticker.C:
			if err := flushBatch(&batch, flush); err != nil {
				return err
			}
		}
	}
}

// Stop halts the shipper and flushes remaining events.
func (s *Shipper) Stop() error {
	s.stopMu.Lock()
	defer s.stopMu.Unlock()
	if s.stopped {
		return nil
	}
	s.stopped = true
	close(s.stopCh)
	s.wg.Wait()
	return nil
}

func flushBatch(batch *[]specs.ThreatEvent, flush func() error) error {
	if err := flush(); err != nil {
		return err
	}
	*batch = nil
	return nil
}

func (s *Shipper) sendBatch(events []specs.ThreatEvent) error {
	payload, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("marshal batch: %w", err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(payload); err != nil {
		return fmt.Errorf("gzip batch: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gzip: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, s.cfg.AggregatorURL, &buf)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("post batch: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("aggregator returned %d", resp.StatusCode)
	}
	return nil
}
