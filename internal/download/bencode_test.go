package download

import (
	"reflect"
	"testing"
)

func TestBencode_Integer(t *testing.T) {
	data := []byte("i42e")
	val, err := UnmarshalBencode(data)
	if err != nil {
		t.Fatalf("Unmarshal integer error: %v", err)
	}
	if val != int64(42) {
		t.Errorf("Expected 42, got %v", val)
	}

	encoded, err := MarshalBencode(int64(42))
	if err != nil {
		t.Fatalf("Marshal integer error: %v", err)
	}
	if string(encoded) != "i42e" {
		t.Errorf("Expected i42e, got %s", encoded)
	}
}

func TestBencode_String(t *testing.T) {
	data := []byte("4:spam")
	val, err := UnmarshalBencode(data)
	if err != nil {
		t.Fatalf("Unmarshal string error: %v", err)
	}
	if val != "spam" {
		t.Errorf("Expected 'spam', got %v", val)
	}

	encoded, err := MarshalBencode("spam")
	if err != nil {
		t.Fatalf("Marshal string error: %v", err)
	}
	if string(encoded) != "4:spam" {
		t.Errorf("Expected 4:spam, got %s", encoded)
	}
}

func TestBencode_List(t *testing.T) {
	data := []byte("l4:spami42ee")
	val, err := UnmarshalBencode(data)
	if err != nil {
		t.Fatalf("Unmarshal list error: %v", err)
	}
	expected := []interface{}{"spam", int64(42)}
	if !reflect.DeepEqual(val, expected) {
		t.Errorf("Expected %v, got %v", expected, val)
	}

	encoded, err := MarshalBencode(expected)
	if err != nil {
		t.Fatalf("Marshal list error: %v", err)
	}
	if string(encoded) != "l4:spami42ee" {
		t.Errorf("Expected l4:spami42ee, got %s", encoded)
	}
}

func TestBencode_Dict(t *testing.T) {
	data := []byte("d3:bar4:spam3:fooi42ee")
	val, err := UnmarshalBencode(data)
	if err != nil {
		t.Fatalf("Unmarshal dict error: %v", err)
	}
	dict, ok := val.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map[string]interface{}, got %T", val)
	}
	if dict["bar"] != "spam" || dict["foo"] != int64(42) {
		t.Errorf("Dict contents mismatch: %v", dict)
	}

	encoded, err := MarshalBencode(dict)
	if err != nil {
		t.Fatalf("Marshal dict error: %v", err)
	}
	if string(encoded) != "d3:bar4:spam3:fooi42ee" {
		t.Errorf("Expected sorted dict d3:bar4:spam3:fooi42ee, got %s", encoded)
	}
}
