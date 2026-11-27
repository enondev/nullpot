// Package obs provides Prometheus metrics, structured logging, and
// distributed tracing for the nullpot sensor.
package obs

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for the sensor.
type Metrics struct {
	// Trap events received, by module and event type.
	TrapEventsTotal *prometheus.CounterVec

	// Trap events dropped due to channel overflow.
	EventsDroppedTotal *prometheus.CounterVec

	// Current number of events in the channel buffer.
	ChannelSize *prometheus.GaugeVec

	// Sensor uptime seconds.
	UptimeSeconds prometheus.Gauge

	// Canary tokens generated and validated.
	CanaryTokensTotal *prometheus.CounterVec

	// HTTP requests served by the decoy trap.
	HTTPRequestsTotal *prometheus.CounterVec

	// HTTP request duration in seconds.
	HTTPRequestDuration *prometheus.HistogramVec

	// Shipper batch operations.
	ShipperBatchesTotal *prometheus.CounterVec

	// Shipper batch failures.
	ShipperBatchFailures *prometheus.CounterVec

	// Widenet listener stats.
	WidenetPacketsTotal *prometheus.CounterVec
}

// NewMetrics creates and registers all sensor metrics.
func NewMetrics() *Metrics {
	m := &Metrics{
		TrapEventsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_trap_events_total",
				Help: "Total trap events emitted by module and type",
			},
			[]string{"module", "event_type"},
		),
		EventsDroppedTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_events_dropped_total",
				Help: "Total events dropped due to channel overflow",
			},
			[]string{"module"},
		),
		ChannelSize: promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "nullpot_channel_size",
				Help: "Current number of events in the buffered channel",
			},
			[]string{"channel"},
		),
		UptimeSeconds: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "nullpot_uptime_seconds",
				Help: "Sensor uptime in seconds",
			},
		),
		CanaryTokensTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_canary_tokens_total",
				Help: "Total canary tokens generated and validated",
			},
			[]string{"kind", "action"},
		),
		HTTPRequestsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_http_requests_total",
				Help: "Total HTTP requests served by decoy trap",
			},
			[]string{"route", "method", "status_code"},
		),
		HTTPRequestDuration: promauto.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "nullpot_http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
			},
			[]string{"route", "method"},
		),
		ShipperBatchesTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_shipper_batches_total",
				Help: "Total batches shipped to aggregator",
			},
			[]string{"status"},
		),
		ShipperBatchFailures: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_shipper_batch_failures_total",
				Help: "Total batch shipping failures",
			},
			[]string{"error_type"},
		),
		WidenetPacketsTotal: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nullpot_widenet_packets_total",
				Help: "Total packets captured by widenet listener",
			},
			[]string{"network", "src_ip"},
		),
	}
	return m
}

// Handler returns an HTTP handler that serves Prometheus metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.Handler()
}

// RecordTrapEvent increments the trap events counter.
func (m *Metrics) RecordTrapEvent(module, eventType string) {
	m.TrapEventsTotal.WithLabelValues(module, eventType).Inc()
}

// RecordEventDropped increments the dropped events counter.
func (m *Metrics) RecordEventDropped(module string) {
	m.EventsDroppedTotal.WithLabelValues(module).Inc()
}

// SetChannelSize sets the channel size gauge.
func (m *Metrics) SetChannelSize(channel string, size float64) {
	m.ChannelSize.WithLabelValues(channel).Set(size)
}

// SetUptime sets the uptime gauge.
func (m *Metrics) SetUptime(seconds float64) {
	m.UptimeSeconds.Set(seconds)
}

// RecordCanaryToken increments the canary token counter.
func (m *Metrics) RecordCanaryToken(kind, action string) {
	m.CanaryTokensTotal.WithLabelValues(kind, action).Inc()
}

// RecordHTTPRequest records an HTTP request with duration.
func (m *Metrics) RecordHTTPRequest(route, method, statusCode string, duration float64) {
	m.HTTPRequestsTotal.WithLabelValues(route, method, statusCode).Inc()
	m.HTTPRequestDuration.WithLabelValues(route, method).Observe(duration)
}

// RecordShipperBatch records a shipper batch operation.
func (m *Metrics) RecordShipperBatch(status string) {
	m.ShipperBatchesTotal.WithLabelValues(status).Inc()
}

// RecordShipperBatchFailure records a shipper batch failure.
func (m *Metrics) RecordShipperBatchFailure(errorType string) {
	m.ShipperBatchFailures.WithLabelValues(errorType).Inc()
}

// RecordWidenetPacket records a captured packet.
func (m *Metrics) RecordWidenetPacket(network, srcIP string) {
	m.WidenetPacketsTotal.WithLabelValues(network, srcIP).Inc()
}
