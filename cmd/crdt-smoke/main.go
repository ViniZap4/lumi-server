// crdt-smoke is a throwaway sanity probe for the cgo wrapper around
// yffi/yrs. Built once during Phase 2.2 bring-up; safe to delete once
// the wrapper has automated tests.
package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/ViniZap4/lumi-server/internal/crdt"
)

func main() {
	d := crdt.NewDoc()
	defer d.Close()

	t, err := d.Text()
	check(err)
	fmt.Printf("initial: %q\n", t)

	u1, err := d.ApplyTextDiff("Hello, world!\n", "tui-diff")
	check(err)
	fmt.Printf("u1: %d bytes\n", len(u1))

	t, _ = d.Text()
	fmt.Printf("after u1: %q\n", t)

	u2, err := d.ApplyTextDiff("Hello, Lumi!\nLine 2\n", "tui-diff")
	check(err)
	fmt.Printf("u2 (delta): %d bytes\n", len(u2))

	t, _ = d.Text()
	fmt.Printf("after u2: %q\n", t)

	sv, err := d.StateVectorV1()
	check(err)
	fmt.Printf("state vector: %s (%d bytes)\n", base64.StdEncoding.EncodeToString(sv), len(sv))

	state, err := d.EncodeStateAsUpdate()
	check(err)
	fmt.Printf("full state: %d bytes\n", len(state))

	// Reload + replay.
	d2, err := crdt.LoadDoc(state)
	check(err)
	defer d2.Close()
	t2, err := d2.Text()
	check(err)
	fmt.Printf("reloaded: %q\n", t2)
	if t2 != t {
		fmt.Fprintln(os.Stderr, "FAIL: reload text mismatch")
		os.Exit(2)
	}

	// Empty-load path.
	d3, err := crdt.LoadDoc(nil)
	check(err)
	defer d3.Close()
	t3, _ := d3.Text()
	if t3 != "" {
		fmt.Fprintln(os.Stderr, "FAIL: empty load not empty")
		os.Exit(2)
	}

	fmt.Println("OK")
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}
