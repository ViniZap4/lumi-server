package fs

import (
	"bytes"
	"strings"
	"testing"
)

func TestFrontmatter_RoundTripWithBodyHorizontalRule(t *testing.T) {
	front := map[string]any{
		"id":    "example",
		"title": "Example Note",
		"tags":  []any{"a", "b"},
	}
	body := []byte("# Heading\n\n---\n\nA paragraph after a horizontal rule.\n")

	encoded, err := WriteFrontmatter(front, body)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	gotFront, gotBody, err := ParseFrontmatter(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if gotFront["id"] != "example" {
		t.Fatalf("id round-trip failed: %#v", gotFront["id"])
	}
	if gotFront["title"] != "Example Note" {
		t.Fatalf("title round-trip failed: %#v", gotFront["title"])
	}
	if !bytes.Contains(gotBody, []byte("---")) {
		t.Fatalf("body lost the horizontal rule: %q", gotBody)
	}
	if !bytes.Contains(gotBody, []byte("A paragraph after a horizontal rule.")) {
		t.Fatalf("body content lost: %q", gotBody)
	}
}

func TestFrontmatter_RejectsUnclosed(t *testing.T) {
	data := []byte("---\ntitle: never closed\nbody but no fence\n")
	if _, _, err := ParseFrontmatter(data); err == nil {
		t.Fatal("expected error for unclosed frontmatter")
	}
}

func TestFrontmatter_NoFenceMeansNoFrontmatter(t *testing.T) {
	data := []byte("# Just markdown\n\nNo YAML here.\n")
	front, body, err := ParseFrontmatter(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(front) != 0 {
		t.Fatalf("expected empty front, got %#v", front)
	}
	if !bytes.Equal(body, data) {
		t.Fatalf("body should equal input verbatim")
	}
}

func TestFrontmatter_MetacharactersInTags(t *testing.T) {
	front := map[string]any{
		"title": "Edge: cases — # special",
		"tags":  []any{"a:b", "with #hash", "quoted \"value\""},
	}
	encoded, err := WriteFrontmatter(front, []byte("body\n"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	gotFront, _, err := ParseFrontmatter(encoded)
	if err != nil {
		t.Fatalf("parse: %v\nencoded:\n%s", err, encoded)
	}
	if gotFront["title"] != "Edge: cases — # special" {
		t.Fatalf("title escaping failed: %#v", gotFront["title"])
	}
	tags, ok := gotFront["tags"].([]any)
	if !ok {
		t.Fatalf("tags type: %T", gotFront["tags"])
	}
	if len(tags) != 3 {
		t.Fatalf("tags length = %d", len(tags))
	}
	if tags[0] != "a:b" || tags[1] != "with #hash" || tags[2] != "quoted \"value\"" {
		t.Fatalf("tags content: %#v", tags)
	}
}

func TestFrontmatter_UnicodeTitle(t *testing.T) {
	front := map[string]any{"title": "日本語のメモ — café 🌙"}
	encoded, err := WriteFrontmatter(front, []byte("body"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	got, _, err := ParseFrontmatter(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got["title"] != "日本語のメモ — café 🌙" {
		t.Fatalf("unicode round-trip failed: %#v", got["title"])
	}
}

func TestFrontmatter_EmptyBody(t *testing.T) {
	front := map[string]any{"id": "empty"}
	encoded, err := WriteFrontmatter(front, nil)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if !strings.HasSuffix(string(encoded), "---\n") {
		t.Fatalf("expected trailing fence, got %q", encoded)
	}
	gotFront, gotBody, err := ParseFrontmatter(encoded)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if gotFront["id"] != "empty" {
		t.Fatalf("id mismatch")
	}
	if len(bytes.TrimSpace(gotBody)) != 0 {
		t.Fatalf("expected empty body, got %q", gotBody)
	}
}
