// Package obs provides structured logging for the nullpot aggregator.
package obs

import (
	"context"
	"io"
	"log/slog"
	"os"
	"time"
)

// Logger wraps slog.Logger with nullpot-specific context.
type Logger struct {
	*slog.Logger
}

// NewLogger creates a new structured logger.
func NewLogger(w io.Writer, level slog.Level) *Logger {
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: true,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.String(slog.TimeKey, a.Value.Time().Format(time.RFC3339Nano))
			}
			if a.Key == slog.LevelKey {
				return slog.String("level", a.Value.String())
			}
			return a
		},
	}
	handler := slog.NewJSONHandler(w, opts)
	return &Logger{slog.New(handler)}
}

// NewDefaultLogger creates a logger writing to stdout at info level.
func NewDefaultLogger() *Logger {
	return NewLogger(os.Stdout, slog.LevelInfo)
}

// Fields is a type for structured log fields.
type Fields map[string]any

// Info logs an info message with fields.
func (l *Logger) Info(msg string, fields Fields) {
	l.log(slog.LevelInfo, msg, fields)
}

// Warn logs a warning message with fields.
func (l *Logger) Warn(msg string, fields Fields) {
	l.log(slog.LevelWarn, msg, fields)
}

// Error logs an error message with fields.
func (l *Logger) Error(msg string, fields Fields) {
	l.log(slog.LevelError, msg, fields)
}

// Debug logs a debug message with fields.
func (l *Logger) Debug(msg string, fields Fields) {
	l.log(slog.LevelDebug, msg, fields)
}

func (l *Logger) log(level slog.Level, msg string, fields Fields) {
	l.Logger.Log(context.Background(), level, msg, slogAnyFields(fields)...)
}

func slogAnyFields(fields Fields) []any {
	args := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}
	return args
}

// EventFields creates standard fields for ingest events.
func EventFields(module, status, srcIP string) Fields {
	fields := Fields{
		"module": module,
		"status": status,
		"src_ip": srcIP,
	}
	return fields
}

// ThreatFields creates standard fields for threat events.
func ThreatFields(eventUID, findingType, srcIP string, score float64) Fields {
	return Fields{
		"event_uid":    eventUID,
		"finding_type": findingType,
		"src_ip":       srcIP,
		"risk_score":   score,
	}
}

// XARFFields creates standard fields for XARF reports.
func XARFFields(reportUUID, provider, status string) Fields {
	return Fields{
		"report_uuid": reportUUID,
		"provider":    provider,
		"status":      status,
	}
}

// Format is used for fmt.Stringer compliance in slog.
type Format string

func (f Format) String() string {
	return string(f)
}
