package download

import (
	"strings"
	"testing"
)

func TestExpandBatchLinks_NumericRange(t *testing.T) {
	input := "https://example.com/assets/tile_[01-04].png"
	links, err := ExpandBatchLinks(input)
	if err != nil {
		t.Fatalf("ExpandBatchLinks failed: %v", err)
	}

	expected := []string{
		"https://example.com/assets/tile_01.png",
		"https://example.com/assets/tile_02.png",
		"https://example.com/assets/tile_03.png",
		"https://example.com/assets/tile_04.png",
	}

	if len(links) != len(expected) {
		t.Fatalf("Expected %d links, got %d", len(expected), len(links))
	}

	for i := range expected {
		if links[i] != expected[i] {
			t.Errorf("Link[%d] = %q, expected %q", i, links[i], expected[i])
		}
	}
}

func TestExpandBatchLinks_AlphaRange(t *testing.T) {
	input := "https://archive.org/download/book_part_[a-c].pdf"
	links, err := ExpandBatchLinks(input)
	if err != nil {
		t.Fatalf("ExpandBatchLinks failed: %v", err)
	}

	expected := []string{
		"https://archive.org/download/book_part_a.pdf",
		"https://archive.org/download/book_part_b.pdf",
		"https://archive.org/download/book_part_c.pdf",
	}

	if len(links) != len(expected) {
		t.Fatalf("Expected %d links, got %d", len(expected), len(links))
	}

	for i := range expected {
		if links[i] != expected[i] {
			t.Errorf("Link[%d] = %q, expected %q", i, links[i], expected[i])
		}
	}
}

func TestExpandBatchLinks_MultiLine(t *testing.T) {
	input := `
		https://example.com/file1.zip
		releases.ubuntu.com/24.04/ubuntu.iso
		"https://cdn.example.org/archive.tar.gz"
	`

	links, err := ExpandBatchLinks(input)
	if err != nil {
		t.Fatalf("ExpandBatchLinks failed: %v", err)
	}

	if len(links) != 3 {
		t.Fatalf("Expected 3 links, got %d", len(links))
	}

	if !strings.HasPrefix(links[1], "https://releases.ubuntu.com") {
		t.Errorf("Expected scheme normalization on item 2, got %q", links[1])
	}
	if strings.Contains(links[2], `"`) {
		t.Errorf("Expected quote stripping on item 3, got %q", links[2])
	}
}
