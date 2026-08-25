// Package database opens the pgx connection pool and registers the custom
// Postgres enum-array type so the IdpProvider[] column encodes/decodes correctly.
package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// enumTypes are custom Postgres types (and their array forms) that pgx must learn
// on each connection.
//
// The names MUST be double-quoted: LoadType resolves via `$1::text::regtype`, and
// regtype's input parser case-folds unquoted identifiers. The DDL created these
// types double-quoted (mixed case), so a bare "IdpProvider" resolves to
// "idpprovider", which does not exist — AfterConnect would then fail on EVERY
// connection, making database.New always error.
var enumTypes = []string{
	`"IdpProvider"`, `"_IdpProvider"`, // allowed_idp_providers IdpProvider[]
}

// Options sizes the pool. A zero field means "leave whatever the connection
// string produced", so a caller that does not care can pass Options{}.
type Options struct {
	// MaxConns caps connections from THIS process. pgx would otherwise derive it
	// from the local CPU count, which says nothing about what the database can
	// serve — the total is really MaxConns x replicas, and Postgres starts
	// refusing connections well before the application notices.
	MaxConns int32

	// MinConns keeps connections warm. Worth setting here because every new
	// connection pays for AfterConnect below, so a pool that has drained to zero
	// makes the next user wait for type registration before their login is even
	// looked at.
	MinConns int32
}

// New opens and verifies a pool. Migrations must already be applied (the enum type
// registration below requires the types to exist).
func New(ctx context.Context, url string, opts Options) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("database: parse url: %w", err)
	}
	if opts.MaxConns > 0 {
		cfg.MaxConns = opts.MaxConns
	}
	if opts.MinConns > 0 {
		cfg.MinConns = opts.MinConns
	}

	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		for _, name := range enumTypes {
			t, err := conn.LoadType(ctx, name)
			if err != nil {
				return fmt.Errorf("database: load type %q (are migrations applied?): %w", name, err)
			}
			conn.TypeMap().RegisterType(t)
		}
		return nil
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("database: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: ping: %w", err)
	}
	return pool, nil
}
