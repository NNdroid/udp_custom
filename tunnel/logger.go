package tunnel

import (
	"log"
	"strings"
)

// Logger receives all diagnostic output of the tunnel endpoints. Embedders
// plug their own implementation (or NopLogger to silence); the CLI wires a
// level-filtered std logger. Methods must be safe for concurrent use — the
// server and client call them from multiple goroutines.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

// Nop discards everything.
var Nop Logger = nopLogger{}

// StdLogger writes every message through the standard log package with the
// protocol's [DEBUG]/[INFO]/[WARN]/[ERROR] prefixes. Unfiltered.
var StdLogger Logger = stdLogger{}

type stdLogger struct{}

func (stdLogger) Debugf(format string, args ...any) { log.Printf("[DEBUG] "+format, args...) }
func (stdLogger) Infof(format string, args ...any)  { log.Printf("[INFO] "+format, args...) }
func (stdLogger) Warnf(format string, args ...any)  { log.Printf("[WARN] "+format, args...) }
func (stdLogger) Errorf(format string, args ...any) { log.Printf("[ERROR] "+format, args...) }

// LogLevel mirrors the config "log_level" values: debug=0 … error=3.
// Unknown values default to info (1).
func LogLevel(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return 0
	case "info":
		return 1
	case "warn", "warning":
		return 2
	case "error":
		return 3
	default:
		return 1
	}
}

// levelLogger filters a Logger by verbosity: messages more verbose than level
// are dropped (0 = debug … 3 = error only).
type levelLogger struct {
	next  Logger
	level int
}

// NewLevelLogger wraps next so only messages at severity >= level pass
// through. next == nil falls back to StdLogger.
func NewLevelLogger(level int, next Logger) Logger {
	if next == nil {
		next = StdLogger
	}
	return levelLogger{next: next, level: level}
}

func (l levelLogger) Debugf(format string, args ...any) {
	if l.level <= 0 {
		l.next.Debugf(format, args...)
	}
}
func (l levelLogger) Infof(format string, args ...any) {
	if l.level <= 1 {
		l.next.Infof(format, args...)
	}
}
func (l levelLogger) Warnf(format string, args ...any) {
	if l.level <= 2 {
		l.next.Warnf(format, args...)
	}
}
func (l levelLogger) Errorf(format string, args ...any) {
	if l.level <= 3 {
		l.next.Errorf(format, args...)
	}
}

// resolveLogger is the config precedence: an injected Logger wins over the
// string level; without either the standard logger runs unfiltered.
func resolveLogger(injected Logger, level string) Logger {
	if injected != nil {
		return injected
	}
	if level == "" {
		return StdLogger
	}
	return NewLevelLogger(LogLevel(level), StdLogger)
}
