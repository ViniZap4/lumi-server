package crdt

import (
	"encoding/hex"
	"errors"
	"testing"
)

// yjsUpdates are v1 updates produced by Yjs 13.6 (JS), covering every
// content kind the guard accepts: text, deletes, formats, embeds, maps
// with every Any tag, nested types and XML. Each is the hex of
// Y.encodeStateAsUpdate (or a delta since a state vector) on a doc that
// exercises that kind; regenerate from the web client's yjs if Yjs ever
// changes its encoding.
var yjsUpdates = map[string]string{
	"text":        "0101eaacf9b00100040107636f6e74656e74106f6cc3a120f09f9880206d756e646f0a00",
	"textDelta":   "0101eaacf9b0010dc4eaacf9b00100eaacf9b001010378797a01eaacf9b001010203",
	"textFull":    "0105eaacf9b00100040107636f6e74656e74016f84eaacf9b00100016c81eaacf9b001010384eaacf9b001040aefbfbd206d756e646f0ac4eaacf9b00100eaacf9b001010378797a01eaacf9b001010203",
	"formatEmbed": "0107bcb9e0aa0900060107636f6e74656e7404626f6c64047472756584bcb9e0aa090002626f84bcb9e0aa0902026c6486bcb9e0aa090404626f6c64046e756c6c85bcb9e0aa0905117b22696d616765223a22782e706e67227d46bcb9e0aa0900066974616c69630474727565c6bcb9e0aa0902bcb9e0aa0903066974616c6963046e756c6c00",
	"mapAny":      "010aa2f1ece30b002801046d657461016e017d012801046d6574610166017c3fc000002801046d65746101730177037374722801046d657461016201782801046d657461036e696c017e2801046d657461036172720175037d017701617601016b75017d022301046d6574610362696e030102032801046d65746103626967017a00000100000000002701046d65746103737562000800a2f1ece30b080177017800",
	"xml":         "0104e8a2b2930500070103786d6c0301702800e8a2b293050005636c617373017701630700e8a2b2930500060400e8a2b293050202686900",
	"deleted":     "01039e8cc6e00c00040107636f6e74656e740161819e8cc6e00c0003849e8cc6e00c03026566019e8cc6e00c010103",
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestUpdateGuardAcceptsYjsUpdates(t *testing.T) {
	for name, h := range yjsUpdates {
		u := mustHex(t, h)
		if err := checkUpdateV1(u); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		d := NewDoc()
		if err := d.ApplyUpdate(u); err != nil {
			t.Errorf("%s: apply: %v", name, err)
		}
		d.Close()
	}
}

func TestUpdateGuardAcceptsYrsUpdates(t *testing.T) {
	d := NewDoc()
	defer d.Close()
	for _, s := range []string{"", "a", "olá 😀\n", "linha 1\nlinha 2\n", "x"} {
		u, err := d.ApplyTextDiff(s, "t")
		if err != nil {
			t.Fatal(err)
		}
		if len(u) > 0 {
			if err := checkUpdateV1(u); err != nil {
				t.Fatalf("delta for %q: %v", s, err)
			}
		}
	}
	full, _ := d.EncodeStateAsUpdate()
	if err := checkUpdateV1(full); err != nil {
		t.Fatalf("full state: %v", err)
	}
	if err := checkUpdateV1([]byte{0, 0}); err != nil {
		t.Fatalf("empty update: %v", err)
	}
}

// TestUpdateGuardRejectsNul is the FuzzApplyUpdate crasher: a Yjs client
// inserting "a\x00b" used to abort the server on the next Text() (yffi
// panics in CString::new, and a panic cannot unwind through cgo).
func TestUpdateGuardRejectsNul(t *testing.T) {
	nul := mustHex(t, "01019ec9a9f30400040107636f6e74656e740361006200")
	d := NewDoc()
	defer d.Close()
	if err := d.ApplyUpdate(nul); !errors.Is(err, ErrUnsafeUpdate) {
		t.Fatalf("ApplyUpdate err = %v, want ErrUnsafeUpdate", err)
	}
	if _, err := d.ApplyUpdateChanged(nul); !errors.Is(err, ErrUnsafeUpdate) {
		t.Fatalf("ApplyUpdateChanged err = %v, want ErrUnsafeUpdate", err)
	}
	if _, err := LoadDoc(nul); !errors.Is(err, ErrUnsafeUpdate) {
		t.Fatalf("LoadDoc err = %v, want ErrUnsafeUpdate", err)
	}
	if s, err := d.Text(); err != nil || s != "" {
		t.Fatalf("doc changed: %q %v", s, err)
	}
	if _, err := d.ApplyTextDiff("a\x00b", ""); !errors.Is(err, ErrUnsafeUpdate) {
		t.Fatalf("ApplyTextDiff err = %v, want ErrUnsafeUpdate", err)
	}
}

func TestUpdateGuardRejects(t *testing.T) {
	text := mustHex(t, yjsUpdates["text"])
	badUTF8 := append([]byte(nil), text...)
	// "olá": the 2-byte 'á' (c3 a1) becomes c3 41, invalid UTF-8.
	for i := range badUTF8 {
		if badUTF8[i] == 0xc3 && badUTF8[i+1] == 0xa1 {
			badUTF8[i+1] = 0x41
			break
		}
	}
	cases := map[string][]byte{
		"truncated":   text[:len(text)-5],
		"invalidUTF8": badUTF8,
		"move":        {1, 1, 1, 0, 0x0b | 0x80, 1, 0, 0, 0, 0},
		"weakType":    {1, 1, 1, 0, 0x07, 1, 1, 'c', 7, 0},
		"subdoc":      {1, 1, 1, 0, 0x09, 1, 1, 'c', 1, 'g', 126, 0},
		"hugeCount":   {0xff, 0xff, 0xff, 0xff, 0x0f},
		"badAnyTag":   {1, 1, 1, 0, 0x08, 1, 1, 'm', 1, 0x10, 0},
	}
	for name, u := range cases {
		if err := checkUpdateV1(u); !errors.Is(err, ErrUnsafeUpdate) {
			t.Errorf("%s: err = %v, want ErrUnsafeUpdate", name, err)
		}
	}
}
