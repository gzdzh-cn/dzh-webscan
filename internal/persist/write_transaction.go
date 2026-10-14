package persist

import (
	"context"
	"database/sql"
	"time"
)

type SQLWriter interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// WriteTx reserves the SQLite writer before any reads. A deferred transaction
// can otherwise lose its WAL snapshot while another process writes live data.
type WriteTx struct {
	conn *sql.Conn
	ctx  context.Context
	done bool
}

func BeginWrite(ctx context.Context, db *sql.DB) (*WriteTx, error) {
	c, e := db.Conn(ctx)
	if e != nil {
		return nil, e
	}
	if _, e = c.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
		c.Close()
		return nil, e
	}
	return &WriteTx{conn: c, ctx: ctx}, nil
}

func (t *WriteTx) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return t.conn.ExecContext(ctx, q, args...)
}
func (t *WriteTx) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return t.conn.QueryRowContext(ctx, q, args...)
}
func (t *WriteTx) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return t.conn.QueryContext(ctx, q, args...)
}
func (t *WriteTx) Commit() error {
	if t.done {
		return sql.ErrTxDone
	}
	if _, e := t.conn.ExecContext(t.ctx, "COMMIT"); e != nil {
		return e
	}
	t.done = true
	return t.conn.Close()
}
func (t *WriteTx) Rollback() error {
	if t.done {
		return sql.ErrTxDone
	}
	t.done = true
	// Cancellation must not return a connection with an open transaction.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, e := t.conn.ExecContext(ctx, "ROLLBACK")
	closeErr := t.conn.Close()
	if e != nil {
		return e
	}
	return closeErr
}
