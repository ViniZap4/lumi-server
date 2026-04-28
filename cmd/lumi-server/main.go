// Command lumi-server is the v2 multi-tenant collaborative note server.
//
// This is a foundation stub. Full server wiring (Fiber app, route
// registration, Postgres pool, FS watcher, CRDT engine) lands in subsequent
// commits per the phased rollout in SPEC.md.
package main

import (
	"fmt"
	"os"
)

// Version is overridden at link time via -ldflags="-X main.Version=...".
var Version = "0.0.0-foundation"

func main() {
	fmt.Fprintf(os.Stdout, "lumi-server %s\n", Version)
	fmt.Fprintln(os.Stdout, "v2 foundation only; full server wiring lands in subsequent commits.")
	os.Exit(0)
}
