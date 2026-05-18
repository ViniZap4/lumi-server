package wsync

import (
	"bytes"
	"testing"
)

func TestVarUintRoundtrip(t *testing.T) {
	cases := []uint64{0, 1, 127, 128, 255, 256, 16383, 16384, 1<<32 - 1, 1 << 56}
	for _, want := range cases {
		buf := writeVarUint(nil, want)
		got, n, err := readVarUint(buf)
		if err != nil {
			t.Fatalf("readVarUint(%d): %v", want, err)
		}
		if got != want {
			t.Fatalf("want %d got %d", want, got)
		}
		if n != len(buf) {
			t.Fatalf("consumed %d, encoded %d bytes", n, len(buf))
		}
	}
}

func TestVarBytesRoundtrip(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00},
		[]byte("hello, lumi"),
		bytes.Repeat([]byte{0xAB}, 250),
		bytes.Repeat([]byte{0xCD}, 1<<14),
	}
	for _, payload := range cases {
		buf := writeVarBytes(nil, payload)
		got, n, err := readVarBytes(buf)
		if err != nil {
			t.Fatalf("readVarBytes(len=%d): %v", len(payload), err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload mismatch")
		}
		if n != len(buf) {
			t.Fatalf("consumed %d, encoded %d", n, len(buf))
		}
	}
}

func TestEncodeDecodeSyncStep1(t *testing.T) {
	sv := []byte{0x01, 0x02, 0x03}
	frame := EncodeSyncStep1(sv)
	msg, err := DecodeMessage(frame)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageSync {
		t.Fatalf("type = %d", msg.Type)
	}
	if msg.SyncSub != SyncStep1 {
		t.Fatalf("sub = %d", msg.SyncSub)
	}
	if !bytes.Equal(msg.Body, sv) {
		t.Fatalf("body = %v", msg.Body)
	}
}

func TestEncodeDecodeSyncStep2(t *testing.T) {
	update := bytes.Repeat([]byte{0xEE}, 200)
	frame := EncodeSyncStep2(update)
	msg, err := DecodeMessage(frame)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageSync || msg.SyncSub != SyncStep2 {
		t.Fatalf("header mismatch %+v", msg)
	}
	if !bytes.Equal(msg.Body, update) {
		t.Fatalf("body mismatch")
	}
}

func TestEncodeDecodeSyncUpdate(t *testing.T) {
	update := []byte{0xA0, 0xA1, 0xA2}
	msg, err := DecodeMessage(EncodeSyncUpdate(update))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageSync || msg.SyncSub != SyncUpdate || !bytes.Equal(msg.Body, update) {
		t.Fatalf("roundtrip failed: %+v", msg)
	}
}

func TestEncodeDecodeAwareness(t *testing.T) {
	awareness := []byte{1, 2, 3, 4, 5}
	msg, err := DecodeMessage(EncodeAwareness(awareness))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != MessageAwareness {
		t.Fatalf("type = %d", msg.Type)
	}
	if !bytes.Equal(msg.Body, awareness) {
		t.Fatalf("body mismatch")
	}
}

func TestDecodeRejectsShortFrames(t *testing.T) {
	cases := [][]byte{
		{},
		{MessageSync},                   // no sub-type
		{MessageSync, SyncStep1},        // no body length
		{MessageSync, SyncStep1, 0x05},  // length=5 but no bytes
		{MessageAwareness},              // no length
	}
	for i, frame := range cases {
		if _, err := DecodeMessage(frame); err == nil {
			t.Fatalf("case %d: expected error, got nil for %v", i, frame)
		}
	}
}

func TestDecodeRejectsUnknownType(t *testing.T) {
	if _, err := DecodeMessage([]byte{0xFE}); err == nil {
		t.Fatalf("expected error on unknown message type")
	}
}
