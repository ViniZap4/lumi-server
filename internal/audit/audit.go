// Package audit declares the minimal recorder interface that domain services
// depend on. Concrete implementation lives in internal/storage/pg.
package audit

import (
	"context"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// Recorder writes audit entries. Implementations must be safe for concurrent
// use. Errors should be logged internally; callers may ignore the return for
// non-critical paths but should propagate it for transaction-bound writes.
type Recorder interface {
	Record(ctx context.Context, e domain.AuditEntry) error
}

// Noop is a Recorder that drops everything. Useful in tests.
type Noop struct{}

func (Noop) Record(context.Context, domain.AuditEntry) error { return nil }
