package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Formatter serializes an audit Entry into structured bytes for transport or persistence.
type Formatter interface {
	Format(entry *Entry) ([]byte, error)
	ContentType() string
}

// -----------------------------------------------------------------------------
// JSON Formatter (NDJSON & Pretty)
// -----------------------------------------------------------------------------

// JSONFormatter serializes entries into JSON.
type JSONFormatter struct {
	Pretty   bool
	Sanitize bool
}

// NewJSONFormatter creates a new JSON audit formatter.
func NewJSONFormatter(pretty bool) *JSONFormatter {
	return &JSONFormatter{
		Pretty:   pretty,
		Sanitize: true,
	}
}

func (f *JSONFormatter) ContentType() string {
	return "application/json"
}

func (f *JSONFormatter) Format(entry *Entry) ([]byte, error) {
	e := entry
	if f.Sanitize {
		e = entry.Sanitize()
	}

	var data []byte
	var err error
	if f.Pretty {
		data, err = json.MarshalIndent(e, "", "  ")
	} else {
		data, err = json.Marshal(e)
	}
	if err != nil {
		return nil, err
	}

	// Append trailing newline for newline-delimited JSON (NDJSON) streaming
	if !f.Pretty && !bytes.HasSuffix(data, []byte("\n")) {
		data = append(data, '\n')
	}
	return data, nil
}

// -----------------------------------------------------------------------------
// CloudEvents v1.0.2 Formatter
// -----------------------------------------------------------------------------

// CloudEventsRecord models a CNCF CloudEvents v1.0.2 structured envelope.
type CloudEventsRecord struct {
	SpecVersion     string `json:"specversion"`
	ID              string `json:"id"`
	Source          string `json:"source"`
	Type            string `json:"type"`
	Time            string `json:"time"`
	DataContentType string `json:"datacontenttype"`
	Data            *Entry `json:"data"`
}

// CloudEventsFormatter outputs entries following the CNCF CloudEvents 1.0.2 specification.
type CloudEventsFormatter struct {
	Source string
}

// NewCloudEventsFormatter creates a new CloudEvents formatter with a given source identifier.
func NewCloudEventsFormatter(source string) *CloudEventsFormatter {
	if source == "" {
		source = "ztatic/audit"
	}
	return &CloudEventsFormatter{Source: source}
}

func (f *CloudEventsFormatter) ContentType() string {
	return "application/cloudevents+json"
}

func (f *CloudEventsFormatter) Format(entry *Entry) ([]byte, error) {
	sanitized := entry.Sanitize()
	record := CloudEventsRecord{
		SpecVersion:     "1.0",
		ID:              sanitized.ID,
		Source:          f.Source,
		Type:            "org.ztatic.audit." + sanitized.Action,
		Time:            sanitized.Timestamp.Format(time.RFC3339Nano),
		DataContentType: "application/json",
		Data:            sanitized,
	}

	data, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	return data, nil
}

// -----------------------------------------------------------------------------
// CEF (Common Event Format) Formatter for SIEMs (ArcSight, Splunk, Graylog)
// -----------------------------------------------------------------------------

// CEFFormatter outputs entries in Micro Focus / ArcSight Common Event Format:
// CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
type CEFFormatter struct {
	Vendor  string
	Product string
	Version string
}

// NewCEFFormatter initializes a CEF formatter.
func NewCEFFormatter(vendor, product, version string) *CEFFormatter {
	if vendor == "" {
		vendor = "Ztatic"
	}
	if product == "" {
		product = "Framework"
	}
	if version == "" {
		version = "1.0"
	}
	return &CEFFormatter{
		Vendor:  vendor,
		Product: product,
		Version: version,
	}
}

func (f *CEFFormatter) ContentType() string {
	return "text/plain"
}

func (f *CEFFormatter) Format(entry *Entry) ([]byte, error) {
	sanitized := entry.Sanitize()

	// Map severity to CEF 0-10 numeric scale
	var cefSeverity int
	switch sanitized.Severity {
	case SeverityCritical:
		cefSeverity = 10
	case SeverityError:
		cefSeverity = 7
	case SeverityWarn:
		cefSeverity = 4
	case SeverityInfo:
		fallthrough
	default:
		cefSeverity = 1
	}

	classID := sanitized.Action
	name := fmt.Sprintf("%s: %s", sanitized.Category, sanitized.Action)

	// Build standard extensions
	var ext []string
	if sanitized.Actor.IP != "" {
		ext = append(ext, fmt.Sprintf("src=%s", escapeCEF(sanitized.Actor.IP)))
	}
	if sanitized.Actor.ID != "" {
		ext = append(ext, fmt.Sprintf("suser=%s", escapeCEF(sanitized.Actor.ID)))
	}
	if sanitized.Target.Type != "" || sanitized.Target.ID != "" {
		ext = append(ext, fmt.Sprintf("cs1Label=TargetType cs1=%s cs2Label=TargetID cs2=%s",
			escapeCEF(sanitized.Target.Type), escapeCEF(sanitized.Target.ID)))
	}
	ext = append(ext, fmt.Sprintf("act=%s", escapeCEF(sanitized.Action)))
	ext = append(ext, fmt.Sprintf("outcome=%s", escapeCEF(string(sanitized.Outcome.Status))))
	if sanitized.Outcome.StatusCode > 0 {
		ext = append(ext, fmt.Sprintf("cn1Label=HTTPStatus cn1=%d", sanitized.Outcome.StatusCode))
	}
	if sanitized.Context.RequestID != "" {
		ext = append(ext, fmt.Sprintf("externalId=%s", escapeCEF(sanitized.Context.RequestID)))
	}
	if sanitized.Context.Path != "" {
		ext = append(ext, fmt.Sprintf("request=%s", escapeCEF(sanitized.Context.Path)))
	}
	if sanitized.Outcome.Reason != "" {
		ext = append(ext, fmt.Sprintf("msg=%s", escapeCEF(sanitized.Outcome.Reason)))
	}

	extensionsStr := strings.Join(ext, " ")

	cefLine := fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s\n",
		escapeCEFHeader(f.Vendor),
		escapeCEFHeader(f.Product),
		escapeCEFHeader(f.Version),
		escapeCEFHeader(classID),
		escapeCEFHeader(name),
		cefSeverity,
		extensionsStr,
	)

	return []byte(cefLine), nil
}

func escapeCEFHeader(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

func escapeCEF(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}

// -----------------------------------------------------------------------------
// Text / Console Formatter (Developer Experience)
// -----------------------------------------------------------------------------

// TextFormatter formats an audit entry into a single concise line for terminal logs.
type TextFormatter struct {
	Colorize bool
}

// NewTextFormatter creates a new text formatter with optional ANSI coloring.
func NewTextFormatter(colorize bool) *TextFormatter {
	return &TextFormatter{Colorize: colorize}
}

func (f *TextFormatter) ContentType() string {
	return "text/plain"
}

func (f *TextFormatter) Format(entry *Entry) ([]byte, error) {
	sanitized := entry.Sanitize()

	statusStr := string(sanitized.Outcome.Status)
	sevStr := string(sanitized.Severity)

	if f.Colorize {
		switch sanitized.Outcome.Status {
		case OutcomeSuccess:
			statusStr = "\033[32m" + statusStr + "\033[0m" // Green
		case OutcomeDenied:
			statusStr = "\033[33m" + statusStr + "\033[0m" // Yellow
		case OutcomeFailure, OutcomeError:
			statusStr = "\033[31m" + statusStr + "\033[0m" // Red
		}

		switch sanitized.Severity {
		case SeverityCritical:
			sevStr = "\033[41;97m" + sevStr + "\033[0m" // Red background
		case SeverityError:
			sevStr = "\033[31m" + sevStr + "\033[0m"
		case SeverityWarn:
			sevStr = "\033[33m" + sevStr + "\033[0m"
		}
	}

	actor := sanitized.Actor.ID
	if actor == "" {
		actor = "anonymous"
	}
	if sanitized.Actor.Role != "" {
		actor = fmt.Sprintf("%s(%s)", actor, sanitized.Actor.Role)
	}

	target := ""
	if sanitized.Target.Type != "" || sanitized.Target.ID != "" {
		target = fmt.Sprintf(" target=%s:%s", sanitized.Target.Type, sanitized.Target.ID)
	}

	httpInfo := ""
	if sanitized.Context.Method != "" || sanitized.Context.Path != "" {
		httpInfo = fmt.Sprintf(" [%s %s -> %d (%.1fms)]",
			sanitized.Context.Method, sanitized.Context.Path, sanitized.Outcome.StatusCode, sanitized.Outcome.DurationMs)
	}

	line := fmt.Sprintf("[AUDIT] %s | %s | %s | actor=%s | action=%s%s%s\n",
		sanitized.Timestamp.Format("2006-01-02 15:04:05.000"),
		sevStr,
		statusStr,
		actor,
		sanitized.Action,
		target,
		httpInfo,
	)

	return []byte(line), nil
}
