// Package obs provides OpenTelemetry tracing for the nullpot aggregator.
package obs

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// Tracer wraps the OpenTelemetry tracer.
type Tracer struct {
	tracer trace.Tracer
}

// NewTracer creates a new tracer.
func NewTracer(serviceName string) *Tracer {
	return &Tracer{
		tracer: otel.Tracer(serviceName),
	}
}

// Shutdown shuts down the tracer provider (no-op for global provider).
func (t *Tracer) Shutdown(ctx context.Context) error {
	return nil
}

// Tracer returns the OpenTelemetry tracer.
func (t *Tracer) Tracer() trace.Tracer {
	return t.tracer
}

// StartSpan starts a new span with the given name and attributes.
func (t *Tracer) StartSpan(ctx context.Context, name string, attrs map[string]string) (context.Context, trace.Span) {
	spanAttrs := make([]attribute.KeyValue, 0, len(attrs))
	for k, v := range attrs {
		spanAttrs = append(spanAttrs, attribute.String(k, v))
	}
	ctx, span := t.tracer.Start(ctx, name, trace.WithAttributes(spanAttrs...))
	return ctx, span
}

// RecordSpanError records an error on the span.
func RecordSpanError(span trace.Span, err error) {
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
	}
}

// GetTracer returns the global tracer.
func GetTracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

// ExtractTraceContext extracts trace context from HTTP headers.
func ExtractTraceContext(headers map[string]string) {
	carrier := propagation.MapCarrier(headers)
	propagation.TraceContext{}.Extract(context.Background(), carrier)
}

// InjectTraceContext injects trace context into HTTP headers.
func InjectTraceContext(headers map[string]string, ctx context.Context) {
	carrier := propagation.MapCarrier(headers)
	propagation.TraceContext{}.Inject(ctx, carrier)
}
