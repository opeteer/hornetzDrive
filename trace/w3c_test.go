package trace

import (
	"testing"
)

func TestParseTraceparent_Valid(t *testing.T) {
	header := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	traceID, parentID, sampled, err := ParseTraceparent(header)
	if err != nil {
		t.Fatalf("unexpected error parsing valid header: %v", err)
	}
	if traceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("expected traceID 4bf92f3577b34da6a3ce929d0e0e4736, got %s", traceID)
	}
	if parentID != "00f067aa0ba902b7" {
		t.Errorf("expected parentID 00f067aa0ba902b7, got %s", parentID)
	}
	if !sampled {
		t.Errorf("expected sampled true, got false")
	}

	// Not sampled flag (00)
	headerUnsampled := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"
	_, _, sampled, err = ParseTraceparent(headerUnsampled)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sampled {
		t.Errorf("expected sampled false, got true")
	}
}

func TestParseTraceparent_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{"too short", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7"},
		{"unsupported version ff", "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
		{"all-zero trace ID", "00-00000000000000000000000000000000-00f067aa0ba902b7-01"},
		{"all-zero parent ID", "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"},
		{"invalid hex characters in trace ID", "00-4bf92f3577b34da6a3ce929d0e0e473g-00f067aa0ba902b7-01"},
		{"invalid delimiter", "00_4bf92f3577b34da6a3ce929d0e0e4736_00f067aa0ba902b7_01"},
		{"extra characters in version 00", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := ParseTraceparent(tc.header)
			if err == nil {
				t.Errorf("expected error for header %q, got nil", tc.header)
			}
		})
	}
}

func TestFormatTraceparent(t *testing.T) {
	formatted := FormatTraceparent("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", true)
	expected := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	if formatted != expected {
		t.Errorf("expected %s, got %s", expected, formatted)
	}

	formattedUnsampled := FormatTraceparent("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", false)
	expectedUnsampled := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"
	if formattedUnsampled != expectedUnsampled {
		t.Errorf("expected %s, got %s", expectedUnsampled, formattedUnsampled)
	}
}
