package obs

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// Tracer wraps the OpenTelemetry tracer.
type Tracer struct {
	tracer oteltrace.Tracer
	tp     *trace.TracerProvider
}

// NewTracer creates a new OpenTelemetry tracer provider with OTLP export.
func NewTracer(serviceName, otlpEndpoint string) (*Tracer, error) {
	exp, err := otlptracehttp.New(context.Background(),
		otlptracehttp.WithEndpoint(otlpEndpoint),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion("1.0.0"),
			semconv.DeploymentEnvironment("production"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	tp := trace.NewTracerProvider(
		trace.WithBatcher(exp),
		trace.WithResource(res),
		trace.WithSampler(trace.ParentBased(trace.TraceIDRatioBased(0.1))),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return &Tracer{
		tracer: tp.Tracer(serviceName),
		tp:     tp,
	}, nil
}

// Shutdown shuts down the tracer provider.
func (t *Tracer) Shutdown(ctx context.Context) error {
	if t.tp != nil {
		return t.tp.Shutdown(ctx)
	}
	return nil
}

// Tracer returns the OpenTelemetry tracer.
func (t *Tracer) Tracer() oteltrace.Tracer {
	return t.tracer
}

// StartSpan starts a new span with the given name and attributes.
func (t *Tracer) StartSpan(ctx context.Context, name string, attrs map[string]string) (context.Context, oteltrace.Span) {
	spanAttrs := make([]attribute.KeyValue, 0, len(attrs))
	for k, v := range attrs {
		spanAttrs = append(spanAttrs, attribute.String(k, v))
	}
	ctx, span := t.tracer.Start(ctx, name, oteltrace.WithAttributes(spanAttrs...))
	return ctx, span
}

// RecordSpanError records an error on the span.
func RecordSpanError(span oteltrace.Span, err error) {
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		span.RecordError(err)
	}
}

// GetTracer returns the global tracer.
func GetTracer(name string) oteltrace.Tracer {
	return otel.Tracer(name)
}

// ExtractTraceContext extracts trace context from HTTP headers.
func ExtractTraceContext(headers map[string]string) propagation.TextMapCarrier {
	carrier := propagation.MapCarrier(headers)
	propagation.TraceContext{}.Extract(context.Background(), carrier)
	return carrier
}

// InjectTraceContext injects trace context into HTTP headers.
func InjectTraceContext(headers map[string]string, ctx context.Context) {
	carrier := propagation.MapCarrier(headers)
	propagation.TraceContext{}.Inject(ctx, carrier)
}
