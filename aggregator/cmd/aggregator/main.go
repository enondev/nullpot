// Package main is the central ingestion, correlation, and CF sync daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/enondev/nullpot/aggregator/internal/abuse"
	"github.com/enondev/nullpot/aggregator/internal/cloudflare"
	"github.com/enondev/nullpot/aggregator/internal/correlate"
	"github.com/enondev/nullpot/aggregator/internal/ingest"
	"github.com/enondev/nullpot/aggregator/internal/obs"
	"github.com/enondev/nullpot/aggregator/internal/scoring"
	"github.com/enondev/nullpot/specs"
)

func main() {
	listenAddr := flag.String("listen", getEnv("PORT", ":8081"), "Ingest API listen address")
	cfAccountID := flag.String("cf-account", getEnv("CF_ACCOUNT_ID", ""), "Cloudflare account ID")
	cfAPIToken := flag.String("cf-token", getEnv("CF_API_TOKEN", ""), "Cloudflare API token")
	cfKVNamespace := flag.String("cf-kv-ns", getEnv("CF_KV_NAMESPACE", ""), "Cloudflare KV namespace ID")
	cfD1Database := flag.String("cf-d1-db", getEnv("CF_D1_DATABASE", ""), "Cloudflare D1 database ID")
	metricsAddr := flag.String("metrics", ":8091", "Metrics endpoint listen address")

	// Normalize PORT for Render (sets bare number like "10000"; Go needs ":10000")
	if _, err := strconv.Atoi(*listenAddr); err == nil {
		*listenAddr = ":" + *listenAddr
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Shared event channel (bounded, drop-oldest handled by shipper)
	events := make(chan specs.ThreatEvent, 8192)

	// In-memory event store
	eventStore := ingest.NewEventStore()

	// Initialize observability.
	metrics := obs.NewMetrics()

	// Ingest receiver
	recv := ingest.NewReceiver(events, eventStore, specs.Product{
		Name:   "nullpot-aggregator",
		UID:    "aggregator-01",
		Region: "global",
	})

	// Correlation engine
	corrEngine := correlate.NewEngine()

	// Researcher allowlist
	allowlist := correlate.NewAllowlist()

	// Scorer with stub MMDB (configured at Phase 10 with real MaxMind data)
	scorer := scoring.NewScorer(&scoring.StubMMDB{})

	// XARF reporter
	xarfReporter := abuse.XARFReporter{
		Name:    "nullpot",
		Contact: "abuse@nullpot.internal",
	}
	xarfDispatcher := abuse.NewDispatcher(map[string]string{}, xarfReporter)

	// Cloudflare sync (optional, configured if credentials provided)
	var cfSync *cloudflare.Sync
	if *cfAccountID != "" && *cfAPIToken != "" {
		kvu := cloudflare.NewKVUploader(*cfAccountID, *cfAPIToken, *cfKVNamespace)
		d1w := cloudflare.NewD1Writer(*cfAccountID, *cfD1Database, *cfAPIToken)
		cfSync = cloudflare.NewSync(kvu, d1w)
	}

	// Start ingest receiver
	go func() {
		if err := recv.Start(ctx, *listenAddr); err != nil && err != context.Canceled {
			log.Printf("ingest receiver stopped: %v", err)
		}
	}()

	// Process events from ingest channel
	var procWg sync.WaitGroup
	procWg.Add(1)
	go func() {
		defer procWg.Done()
		for ev := range events {
			pc := ProcessingContext{
				Ctx:          ctx,
				Event:        ev,
				Corr:         corrEngine,
				Allowlist:    allowlist,
				Scorer:       scorer,
				XARFReporter: xarfReporter,
				XARF:         xarfDispatcher,
				CFSync:       cfSync,
				Store:        eventStore,
			}
			processEvent(pc)
		}
	}()

	// Health and metrics endpoint.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "ok\n")
	})
	mux.Handle("/metrics", metrics.Handler())
	healthSrv := &http.Server{Addr: *metricsAddr, Handler: mux}
	go func() {
		_ = healthSrv.ListenAndServe()
	}()

	<-ctx.Done()
	log.Println("shutting down aggregator daemon")

	close(events)
	procWg.Wait()

	healthShutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := healthSrv.Shutdown(healthShutdownCtx); err != nil {
		log.Printf("health server shutdown: %v", err)
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ProcessingContext groups all dependencies needed to process a single event.
type ProcessingContext struct {
	Ctx          context.Context
	Event        specs.ThreatEvent
	Corr         *correlate.Engine
	Allowlist    *correlate.Allowlist
	Scorer       *scoring.Scorer
	XARFReporter abuse.XARFReporter
	XARF         *abuse.Dispatcher
	CFSync       *cloudflare.Sync
	Store        *ingest.EventStore
}

func processEvent(ctx ProcessingContext) {
	ev := ctx.Event

	// Check researcher allowlist — skip allowlisted IPs
	if checkAllowlist(ev, ctx.Allowlist) {
		log.Printf("skipping allowlisted IP: %s", ev.SrcEndpoint.IP)
		return
	}

	// Record event to store (bounded, FIFO eviction).
	ctx.Store.Add(ev)

	// Extract C2/IOCs from captured payload.
	extractor := correlate.NewC2Extractor()
	iocs := extractor.Extract(ev.Enrichment.PayloadPreview)

	// Double-verification correlation.
	// Widenet port sweeps are recorded as recon; trap hits are recorded as exploitation.
	corrResult := correlateEvent(ev, ctx.Corr)

	// Risk scoring.
	ttlHours := int(corrResult.TTL / time.Hour)
	inputs := scoring.RiskInputs{
		IP: ev.SrcEndpoint.IP,
		Correlation: scoring.CorrelationResult{
			IsHighConfidence: corrResult.IsHighConfidence,
			ReconSeen:        corrResult.ReconSeen,
			ExploitSeen:      corrResult.ExploitSeen,
			RiskMultiplier:   corrResult.RiskMultiplier,
			TTL:              ttlHours,
		},
		IsConfirmedC2:    corrResult.IsHighConfidence && len(iocs) > 0,
		IsResidentialVPS: false,
		ExtractedIOCs:    iocStrings(iocs),
	}
	riskScore := scoreEvent(inputs, ctx.Scorer)

	log.Printf("event %s: IP=%s score=%.1f level=%s ttl=%dh",
		ev.FindingInfo.UID, ev.SrcEndpoint.IP, riskScore.Score,
		riskScore.RiskLevel, riskScore.TTLHours)

	// XARF dispatch for high-confidence exploitation/malware drops
	if err := dispatchXARF(ev, ctx.XARFReporter, ctx.XARF); err != nil {
		log.Printf("XARF dispatch failed: %v", err)
	}

	// Cloudflare sync (batched, respects free-tier caps)
	if err := syncToCloudflare(ev, riskScore, ctx.CFSync); err != nil {
		log.Printf("CF sync error: %v", err)
	}
}

// checkAllowlist returns true if the IP should be skipped (allowlisted).
func checkAllowlist(ev specs.ThreatEvent, allowlist *correlate.Allowlist) bool {
	return allowlist.IsAllowed(ev.SrcEndpoint.IP)
}

// correlateEvent performs double-verification: recon + exploit from same IP/subnet.
func correlateEvent(ev specs.ThreatEvent, corr *correlate.Engine) correlate.CorrelationResult {
	if ev.Enrichment.Module == "widenet" {
		corr.RecordSweep(ev.SrcEndpoint.IP, ev.Time)
	} else if ev.Enrichment.Module == "http_persona" || ev.Enrichment.Module == "ssh" || ev.Enrichment.Module == "raw_tcp" {
		corr.RecordHit(ev.SrcEndpoint.IP, ev.Time)
	}
	return corr.Correlate(ev.SrcEndpoint.IP, ev.Time)
}

// scoreEvent computes the risk score for the given inputs.
func scoreEvent(inputs scoring.RiskInputs, scorer *scoring.Scorer) scoring.RiskScore {
	return scorer.Score(inputs)
}

// iocStrings converts []correlate.ExtractedIOC to []string.
func iocStrings(iocs []correlate.ExtractedIOC) []string {
	out := make([]string, len(iocs))
	for i, ioc := range iocs {
		out[i] = ioc.Value
	}
	return out
}

// dispatchXARF sends a XARF report for events that warrant it.
func dispatchXARF(ev specs.ThreatEvent, reporter abuse.XARFReporter, xarf *abuse.Dispatcher) error {
	if !abuse.ShouldDispatch(ev) {
		return nil
	}
	report := abuse.BuildReport(ev, reporter)
	return xarf.Dispatch(report)
}

// syncToCloudflare pushes critical events to KV and D1.
func syncToCloudflare(ev specs.ThreatEvent, riskScore scoring.RiskScore, cfSync *cloudflare.Sync) error {
	if cfSync == nil || riskScore.RiskLevel != "critical" {
		return nil
	}
	kvPairs := []cloudflare.KVPair{
		{Key: "ip:" + ev.SrcEndpoint.IP, Value: fmt.Sprintf("score=%.1f level=%s", riskScore.Score, riskScore.RiskLevel)},
	}
	d1Rows := []cloudflare.D1Row{
		{SQL: "INSERT INTO events (ip, score, level, ttl) VALUES (?, ?, ?, ?)",
			Params: []interface{}{ev.SrcEndpoint.IP, riskScore.Score, riskScore.RiskLevel, riskScore.TTLHours}},
	}
	result := cfSync.Run(kvPairs, d1Rows)
	if len(result.Errors) > 0 {
		return result.Errors[0]
	}
	return nil
}
