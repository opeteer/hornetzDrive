package log

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// ANSI color escape sequences
const (
	colorReset   = "\033[0m"
	colorDim     = "\033[90m"
	colorCyan    = "\033[36m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorRed     = "\033[31m"
	colorMagenta = "\033[35m"
	colorBold    = "\033[1m"
)

// ConsoleHandlerOptions contains options for the ConsoleHandler.
type ConsoleHandlerOptions struct {
	Level     slog.Leveler
	AddSource bool
	NoColor   bool
	TimeFormat string
}

// ConsoleHandler is an slog.Handler that writes human-readable, colorized logs to an io.Writer.
type ConsoleHandler struct {
	opts   ConsoleHandlerOptions
	writer io.Writer
	mu     *sync.Mutex
	attrs  []slog.Attr
	groups []string
}

// NewConsoleHandler constructs a new ConsoleHandler.
func NewConsoleHandler(w io.Writer, opts *ConsoleHandlerOptions) *ConsoleHandler {
	var o ConsoleHandlerOptions
	if opts != nil {
		o = *opts
	}
	if o.Level == nil {
		o.Level = slog.LevelInfo
	}
	if o.TimeFormat == "" {
		o.TimeFormat = "15:04:05.000"
	}
	return &ConsoleHandler{
		opts:   o,
		writer: w,
		mu:     &sync.Mutex{},
	}
}

// Enabled reports whether the handler emits log records at the given level.
func (h *ConsoleHandler) Enabled(_ context.Context, level slog.Level) bool {
	minLevel := slog.LevelInfo
	if h.opts.Level != nil {
		minLevel = h.opts.Level.Level()
	}
	return level >= minLevel
}

// Handle formats and writes an slog.Record with colorized terminal styling.
func (h *ConsoleHandler) Handle(_ context.Context, r slog.Record) error {
	var buf bytes.Buffer

	// 1. Timestamp
	t := r.Time
	if t.IsZero() {
		t = time.Now()
	}
	if h.opts.NoColor {
		buf.WriteString(t.Format(h.opts.TimeFormat))
	} else {
		buf.WriteString(colorDim)
		buf.WriteString(t.Format(h.opts.TimeFormat))
		buf.WriteString(colorReset)
	}
	buf.WriteByte(' ')

	// 2. Level Badge
	buf.WriteString(h.formatLevel(r.Level))
	buf.WriteByte(' ')

	// 3. Caller Source (if enabled)
	if h.opts.AddSource && r.PC != 0 {
		fs := runtime.CallersFrames([]uintptr{r.PC})
		f, _ := fs.Next()
		if f.File != "" {
			src := fmt.Sprintf("[%s:%d]", filepath.Base(f.File), f.Line)
			if h.opts.NoColor {
				buf.WriteString(src)
			} else {
				buf.WriteString(colorDim)
				buf.WriteString(src)
				buf.WriteString(colorReset)
			}
			buf.WriteByte(' ')
		}
	}

	// 4. Message
	if h.opts.NoColor {
		buf.WriteString(r.Message)
	} else {
		buf.WriteString(colorBold)
		buf.WriteString(r.Message)
		buf.WriteString(colorReset)
	}

	// 5. Attributes (both from handler and record)
	writeAttr := func(a slog.Attr, prefix string) {
		if a.Equal(slog.Attr{}) {
			return
		}
		key := a.Key
		if prefix != "" {
			key = prefix + "." + key
		}

		buf.WriteByte(' ')
		if h.opts.NoColor {
			fmt.Fprintf(&buf, "%s=%v", key, formatValue(a.Value))
		} else {
			fmt.Fprintf(&buf, "%s%s=%s%v", colorDim, key, colorReset, formatValue(a.Value))
		}
	}

	prefix := ""
	for i, g := range h.groups {
		if i > 0 {
			prefix += "."
		}
		prefix += g
	}

	for _, a := range h.attrs {
		writeAttr(a, prefix)
	}

	r.Attrs(func(a slog.Attr) bool {
		writeAttr(a, prefix)
		return true
	})

	buf.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.writer.Write(buf.Bytes())
	return err
}

func (h *ConsoleHandler) formatLevel(level slog.Level) string {
	if h.opts.NoColor {
		switch {
		case level < slog.LevelInfo:
			return "[DEBUG]"
		case level < slog.LevelWarn:
			return "[INFO ]"
		case level < slog.LevelError:
			return "[WARN ]"
		default:
			return "[ERROR]"
		}
	}

	switch {
	case level < slog.LevelInfo:
		return colorCyan + "[DEBUG]" + colorReset
	case level < slog.LevelWarn:
		return colorGreen + "[INFO ]" + colorReset
	case level < slog.LevelError:
		return colorYellow + "[WARN ]" + colorReset
	default:
		return colorRed + "[ERROR]" + colorReset
	}
}

func formatValue(v slog.Value) any {
	switch v.Kind() {
	case slog.KindString:
		return v.String()
	case slog.KindInt64:
		return v.Int64()
	case slog.KindUint64:
		return v.Uint64()
	case slog.KindFloat64:
		return v.Float64()
	case slog.KindBool:
		return v.Bool()
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		return v.Time().Format(time.RFC3339)
	case slog.KindGroup:
		// Return group attributes formatted as map
		groupAttrs := v.Group()
		m := make(map[string]any, len(groupAttrs))
		for _, a := range groupAttrs {
			m[a.Key] = formatValue(a.Value)
		}
		return m
	default:
		return v.Any()
	}
}

// WithAttrs returns a new ConsoleHandler whose attributes consist of h's attributes followed by attrs.
func (h *ConsoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	newAttrs = append(newAttrs, h.attrs...)
	newAttrs = append(newAttrs, attrs...)

	return &ConsoleHandler{
		opts:   h.opts,
		writer: h.writer,
		mu:     h.mu,
		attrs:  newAttrs,
		groups: h.groups,
	}
}

// WithGroup returns a new ConsoleHandler with group appended to h's groups.
func (h *ConsoleHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	newGroups := make([]string, 0, len(h.groups)+1)
	newGroups = append(newGroups, h.groups...)
	newGroups = append(newGroups, name)

	return &ConsoleHandler{
		opts:   h.opts,
		writer: h.writer,
		mu:     h.mu,
		attrs:  h.attrs,
		groups: newGroups,
	}
}
