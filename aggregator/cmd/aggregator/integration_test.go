package main

import (
	"context"
	"testing"
	"time"

	"github.com/enondev/nullpot/aggregator/internal/abuse"
	"github.com/enondev/nullpot/aggregator/internal/correlate"
	"github.com/enondev/nullpot/aggregator/internal/ingest"
	"github.com/enondev/nullpot/aggregator/internal/scoring"
	"github.com/enondev/nullpot/specs"
)

func makeTestEvent(module, ip string, iocs ...string) specs.ThreatEvent {
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
			UID:   "evt-test-" + ip,
			Title: "test finding",
			Types: []string{"port_scan"},
		},
		Enrichment: specs.Enrichment{
			Module:         module,
			PayloadPreview: "http://example.com/malware",
			PayloadSHA256:  "abc123",
			ExtractedIOCs:  iocs,
		},
	}
}

func TestIntegrationWidenetSweepScores(t *testing.T) {
	ctx := context.Background()
	store := ingest.NewEventStore()
	corr := correlate.NewEngine()
	allowlist := correlate.NewAllowlist()
	scorer := scoring.NewScorer(&scoring.StubMMDB{})
	xarfReporter := abuse.XARFReporter{Name: "test", Contact: "abuse@test.internal"}
	xarf := abuse.NewDispatcher(map[string]string{}, xarfReporter)

	ev := makeTestEvent("widenet", "203.0.113.45")
	pc := ProcessingContext{
		Ctx:          ctx,
		Event:        ev,
		Corr:         corr,
		Allowlist:    allowlist,
		Scorer:       scorer,
		XARFReporter: xarfReporter,
		XARF:         xarf,
		CFSync:       nil,
		Store:        store,
	}
	processEvent(pc)

	if store.Len() != 1 {
		t.Fatalf("expected 1 event in store, got %d", store.Len())
	}
}

func TestIntegrationTrapHitExtractedIOCs(t *testing.T) {
	ctx := context.Background()
	store := ingest.NewEventStore()
	corr := correlate.NewEngine()
	allowlist := correlate.NewAllowlist()
	scorer := scoring.NewScorer(&scoring.StubMMDB{})
	xarfReporter := abuse.XARFReporter{Name: "test", Contact: "abuse@test.internal"}
	xarf := abuse.NewDispatcher(map[string]string{}, xarfReporter)

	ev := makeTestEvent("http_persona", "203.0.113.45", "http://c2.example.com")
	pc := ProcessingContext{
		Ctx:          ctx,
		Event:        ev,
		Corr:         corr,
		Allowlist:    allowlist,
		Scorer:       scorer,
		XARFReporter: xarfReporter,
		XARF:         xarf,
		CFSync:       nil,
		Store:        store,
	}
	processEvent(pc)

	if store.Len() != 1 {
		t.Fatalf("expected 1 event in store, got %d", store.Len())
	}
	evOut := store.All()[0]
	if len(evOut.Enrichment.ExtractedIOCs) == 0 {
		t.Fatal("expected non-empty ExtractedIOCs")
	}
}
