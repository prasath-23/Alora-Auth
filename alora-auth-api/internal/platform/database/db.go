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

// New opens and verifies a pool. Migrations must already be applied (the enum type
// registration below requires the types to exist).
func New(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("database: parse url: %w", err)
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
