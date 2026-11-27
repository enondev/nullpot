// Package obs provides Prometheus metrics, structured logging, and
// distributed tracing for the nullpot aggregator.
package obs

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for the aggregator.
type Metrics struct {
	// Ingest events received, by module and validation status.
	IngestEventsTotal *prometheus.CounterVec

	// Ingest events rejected due to validation failure.
	IngestRejectionsTotal *prometheus.CounterVec

	// Correlation results by classification.
	CorrelationEventsTotal *prometheus.CounterVec

	// Risk scores by risk level.
	RiskScoresTotal *prometheus.CounterVec

	// Risk score distribution (histogram).
	RiskScoreDistribution *prometheus.HistogramVec

	// XARF reports dispatched and failed.
	XARFReportsTotal *prometheus.CounterVec

	// XARF dispatch failures by provider.
	XARFDispatchFailures *prometheus.CounterVec

	// Cloudflare KV writes and failures.
	KVWritesTotal *prometheus.CounterVec

	// Cloudflare D1 row writes and failures.
	D1WritesTotal *prometheus.CounterVec

	// Cloudflare API errors by endpoint.
	CFErrorsTotal *prometheus.CounterVec

	// Aggregator uptime seconds.
	UptimeSeconds prometheus.Gauge

	// In-memory event store size.
	EventStoreSize prometheus.Gauge

	// Canary token callbacks received.
	CanaryCallbacksTotal *prometheus.CounterVec

	// Double-verification correlations by confidence.
	DoubleVerificationCorrelations *prometheus.CounterVec
}

// NewMetrics creates and registers all aggregator metrics.
func NewMetrics() *Metrics {
	m := &Metrics{
		IngestEventsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_ingest_events_total",
				Help: "Total ingest events received by module and status",
			},
			[]string{"module", "status"},
		),
		IngestRejectionsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_ingest_rejections_total",
				Help: "Total ingest events rejected by reason",
			},
			[]string{"reason"},
		),
		CorrelationEventsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_correlation_events_total",
				Help: "Total correlation events by classification",
			},
			[]string{"classification"},
		),
		RiskScoresTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_risk_scores_total",
				Help: "Total risk scores by risk level",
			},
			[]string{"risk_level"},
		),
		RiskScoreDistribution: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "nullpot_risk_score_distribution",
				Help:    "Distribution of risk scores",
				Buckets: prometheus.LinearBuckets(0, 10, 10),
			},
			[]string{"module"},
		),
		XARFReportsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_xarf_reports_total",
				Help: "Total XARF reports dispatched",
			},
			[]string{"provider", "status"},
		),
		XARFDispatchFailures: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_xarf_dispatch_failures_total",
				Help: "Total XARF dispatch failures by provider",
			},
			[]string{"provider", "error_type"},
		),
		KVWritesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_kv_writes_total",
				Help: "Total Cloudflare KV writes",
			},
			[]string{"namespace", "status"},
		),
		D1WritesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_d1_writes_total",
				Help: "Total Cloudflare D1 row writes",
			},
			[]string{"database", "status"},
		),
		CFErrorsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_cloudflare_errors_total",
				Help: "Total Cloudflare API errors by endpoint",
			},
			[]string{"endpoint", "status_code"},
		),
		UptimeSeconds: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "nullpot_aggregator_uptime_seconds",
				Help: "Aggregator uptime in seconds",
			},
		),
		EventStoreSize: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "nullpot_event_store_size",
				Help: "Current number of events in the in-memory store",
			},
		),
		CanaryCallbacksTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_canary_callbacks_total",
				Help: "Total canary token callbacks received",
			},
			[]string{"canary_id", "result"},
		),
		DoubleVerificationCorrelations: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_double_verification_correlations_total",
				Help: "Total double-verification correlations by confidence",
			},
			[]string{"confidence"},
		),
	}
	return m
}

// Handler returns an HTTP handler that serves Prometheus metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.Handler()
}

// RecordIngestEvent records an ingested event.
func (m *Metrics) RecordIngestEvent(module, status string) {
	m.IngestEventsTotal.WithLabelValues(module, status).Inc()
}

// RecordIngestRejection records a rejected event.
func (m *Metrics) RecordIngestRejection(reason string) {
	m.IngestRejectionsTotal.WithLabelValues(reason).Inc()
}

// RecordCorrelationEvent records a correlation event.
func (m *Metrics) RecordCorrelationEvent(classification string) {
	m.CorrelationEventsTotal.WithLabelValues(classification).Inc()
}

// RecordRiskScore records a risk score.
func (m *Metrics) RecordRiskScore(riskLevel string, score float64) {
	m.RiskScoresTotal.WithLabelValues(riskLevel).Inc()
	m.RiskScoreDistribution.WithLabelValues(riskLevel).Observe(score)
}

// RecordXARFReport records a dispatched XARF report.
func (m *Metrics) RecordXARFReport(provider, status string) {
	m.XARFReportsTotal.WithLabelValues(provider, status).Inc()
}

// RecordXARFDispatchFailure records a XARF dispatch failure.
func (m *Metrics) RecordXARFDispatchFailure(provider, errorType string) {
	m.XARFDispatchFailures.WithLabelValues(provider, errorType).Inc()
}

// RecordKVWrite records a KV write operation.
func (m *Metrics) RecordKVWrite(namespace, status string) {
	m.KVWritesTotal.WithLabelValues(namespace, status).Inc()
}

// RecordD1Write records a D1 row write operation.
func (m *Metrics) RecordD1Write(database, status string) {
	m.D1WritesTotal.WithLabelValues(database, status).Inc()
}

// RecordCFError records a Cloudflare API error.
func (m *Metrics) RecordCFError(endpoint string, statusCode int) {
	m.CFErrorsTotal.WithLabelValues(endpoint, string(rune(statusCode))).Inc()
}

// SetUptime sets the uptime gauge.
func (m *Metrics) SetUptime(seconds float64) {
	m.UptimeSeconds.Set(seconds)
}

// SetEventStoreSize sets the event store size gauge.
func (m *Metrics) SetEventStoreSize(size float64) {
	m.EventStoreSize.Set(size)
}

// RecordCanaryCallback records a canary callback.
func (m *Metrics) RecordCanaryCallback(canaryID, result string) {
	m.CanaryCallbacksTotal.WithLabelValues(canaryID, result).Inc()
}

// RecordDoubleVerificationCorrelation records a correlation.
func (m *Metrics) RecordDoubleVerificationCorrelation(confidence string) {
	m.DoubleVerificationCorrelations.WithLabelValues(confidence).Inc()
}
