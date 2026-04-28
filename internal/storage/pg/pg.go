// Package pg implements the Postgres storage layer for lumi v2.
//
// Each domain area gets its own store struct (UserStore, SessionStore, ...).
// Stores share a *pgxpool.Pool injected at construction; they are stateless
// and safe for concurrent use. All queries are parameterised; pgx auto-prepares
// frequently-executed statements at the connection level.
//
// Errors returned from these stores are domain sentinels (domain.ErrNotFound,
// domain.ErrConflict, ...) wrapped with %w so callers can errors.Is them.
// Raw pgx errors never escape this package.
package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

const (
	defaultMaxConns        = 25
	defaultMinConns        = 2
	defaultMaxConnIdleTime = 5 * time.Minute
	defaultMaxConnLifetime = time.Hour
	defaultHealthCheckTick = 30 * time.Second
)

// New constructs a *pgxpool.Pool with sensible defaults. The pool is verified
// with a Ping before being returned. The caller owns Close().
func New(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("pg: parse dsn: %w", err)
	}
	cfg.MaxConns = defaultMaxConns
	cfg.MinConns = defaultMinConns
	cfg.MaxConnIdleTime = defaultMaxConnIdleTime
	cfg.MaxConnLifetime = defaultMaxConnLifetime
	cfg.HealthCheckPeriod = defaultHealthCheckTick

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pg: new pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pg: ping: %w", err)
	}
	return pool, nil
}

// Migrate runs all up-migrations from migrationsDir against the given DSN.
// Idempotent. migrationsDir is a filesystem path.
func Migrate(ctx context.Context, dsn, migrationsDir string) error {
	src := "file://" + migrationsDir
	m, err := migrate.New(src, dsn)
	if err != nil {
		return fmt.Errorf("pg: migrate new: %w", err)
	}
	defer func() {
		_, _ = m.Close()
	}()

	done := make(chan error, 1)
	go func() {
		err := m.Up()
		if err != nil && !errors.Is(err, migrate.ErrNoChange) {
			done <- err
			return
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("pg: migrate up: %w", err)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// errMap translates pgx / pg infrastructure errors into domain sentinels.
// Anything unrecognised is returned unchanged so the caller can wrap it.
func errMap(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case pgerrcode.UniqueViolation:
			return domain.ErrConflict
		case pgerrcode.ForeignKeyViolation:
			return domain.ErrNotFound
		case pgerrcode.CheckViolation, pgerrcode.NotNullViolation:
			return domain.ErrValidation
		}
	}
	return err
}

// runTx executes fn inside a transaction. Commits on success; rolls back
// (best-effort) on any error or panic.
func runTx(ctx context.Context, pool *pgxpool.Pool, fn func(pgx.Tx) error) (err error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("pg: begin tx: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			return
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			err = fmt.Errorf("pg: commit: %w", cerr)
		}
	}()
	return fn(tx)
}
