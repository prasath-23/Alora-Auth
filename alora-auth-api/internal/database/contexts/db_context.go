// Package contexts owns the application's single handle on the database: the pgx
// connection pool, the transactions opened on it, and the registration of the
// custom Postgres types every connection needs.
package contexts

import (
	"context"
	"fmt"

	"github.com/alora/auth/internal/database/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Options sizes the pool. A zero field means "leave whatever the connection
// string produced", so a caller that does not care can pass Options{}.
type Options struct {
	// MaxConns caps connections from THIS process. pgx would otherwise derive it
	// from the local CPU count, which says nothing about what the database can
	// serve — the total is really MaxConns x replicas, and Postgres starts
	// refusing connections well before the application notices.
	MaxConns int32

	// MinConns keeps connections warm, so a pool that has drained to zero does
	// not make the next user wait for a TCP and TLS handshake before their login
	// is even looked at.
	MinConns int32
}

// DbContext is the pool-bound database context. There is one per process.
type DbContext struct {
	pool *pgxpool.Pool
	q    *sqlc.Queries
}

// Connect opens and verifies a pool. The schema must already be built.
//
// No custom types are registered on the connections: every enum the queries use
// is a scalar, which pgx reads and writes as text without being told its OID.
// Only an ARRAY of an enum would need registration, and the schema has none.
func Connect(ctx context.Context, url string, opts Options) (*DbContext, error) {
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

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("database: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: ping: %w", err)
	}
	return &DbContext{pool: pool, q: sqlc.New(pool)}, nil
}

// Close releases every connection. Call it only after the HTTP server has
// drained, so no in-flight request loses its connection mid-transaction.
func (c *DbContext) Close() { c.pool.Close() }

// Ping runs the readiness query (SELECT 1 through udf_HealthCheck).
func (c *DbContext) Ping(ctx context.Context) error {
	_, err := c.q.HealthCheck(ctx)
	return err
}

// Begin opens a transaction. The caller owns it: defer Rollback, which is a no-op
// once Commit has succeeded, and Commit explicitly.
func (c *DbContext) Begin(ctx context.Context) (*TxContext, error) {
	tx, err := c.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &TxContext{tx: tx, q: c.q.WithTx(tx)}, nil
}

// Queries is the generated query surface bound to the pool. Only the table
// services in internal/database/services may call it.
func (c *DbContext) Queries() *sqlc.Queries { return c.q }

// DBTX is the raw executor behind Queries, for the one provisioning statement no
// procedure covers. Only the table services may call it.
func (c *DbContext) DBTX() sqlc.DBTX { return c.pool }

// Pool is the raw pool, for tests that seed and assert with plain SQL.
func (c *DbContext) Pool() *pgxpool.Pool { return c.pool }

// TxContext is a database context bound to one transaction. Every table service
// built from it runs inside that transaction.
type TxContext struct {
	tx pgx.Tx
	q  *sqlc.Queries
}

// Commit commits the transaction. Its error is returned unwrapped.
func (t *TxContext) Commit(ctx context.Context) error { return t.tx.Commit(ctx) }

// Rollback aborts the transaction; after a successful Commit it is a no-op.
func (t *TxContext) Rollback(ctx context.Context) error { return t.tx.Rollback(ctx) }

// Queries is the generated query surface bound to the transaction.
func (t *TxContext) Queries() *sqlc.Queries { return t.q }

// DBTX is the raw executor behind Queries.
func (t *TxContext) DBTX() sqlc.DBTX { return t.tx }

// Querier is what a table service runs against: the pool-bound DbContext or a
// TxContext. Passing a TxContext is how a feature service puts several table
// services into one transaction.
type Querier interface {
	Queries() *sqlc.Queries
	DBTX() sqlc.DBTX
}
