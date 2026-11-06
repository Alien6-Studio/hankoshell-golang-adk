package hankoadk

import (
	"context"
	"database/sql"
	"errors"
)

// PostgresSessionSchema is applied through the application's migration procedure.
// The runtime identity only needs SELECT, INSERT, UPDATE and DELETE on this table.
const PostgresSessionSchema = `CREATE TABLE hanko_sessions (
 scope text NOT NULL, id text NOT NULL, revision text NOT NULL,
 expires_at bigint NOT NULL, lease_until bigint NOT NULL, sealed text NOT NULL,
 PRIMARY KEY (scope,id)
);
CREATE INDEX hanko_sessions_expiry ON hanko_sessions (expires_at);`

// PostgresSessionStore uses atomic conditional updates; no database driver is imposed.
type PostgresSessionStore struct{ DB *sql.DB }

func (s *PostgresSessionStore) Create(ctx context.Context, scope string, value StoredSession) (bool, error) {
	r, err := s.DB.ExecContext(ctx, "INSERT INTO hanko_sessions (scope,id,revision,expires_at,lease_until,sealed) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING", scope, value.ID, value.Revision, value.ExpiresAt, value.LeaseUntil, value.Sealed)
	if err != nil {
		return false, &SessionError{Category: SessionUnavailable}
	}
	count, err := r.RowsAffected()
	return count == 1, err
}
func (s *PostgresSessionStore) Read(ctx context.Context, scope, id string) (*StoredSession, error) {
	var value StoredSession
	err := s.DB.QueryRowContext(ctx, "SELECT id,revision,expires_at,lease_until,sealed FROM hanko_sessions WHERE scope=$1 AND id=$2", scope, id).Scan(&value.ID, &value.Revision, &value.ExpiresAt, &value.LeaseUntil, &value.Sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, &SessionError{Category: SessionUnavailable}
	}
	return &value, nil
}
func (s *PostgresSessionStore) Replace(ctx context.Context, scope, revision string, value StoredSession) (bool, error) {
	r, err := s.DB.ExecContext(ctx, "UPDATE hanko_sessions SET revision=$4,expires_at=$5,lease_until=$6,sealed=$7 WHERE scope=$1 AND id=$2 AND revision=$3", scope, value.ID, revision, value.Revision, value.ExpiresAt, value.LeaseUntil, value.Sealed)
	if err != nil {
		return false, &SessionError{Category: SessionUnavailable}
	}
	count, err := r.RowsAffected()
	return count == 1, err
}
func (s *PostgresSessionStore) Remove(ctx context.Context, scope, id string) error {
	_, err := s.DB.ExecContext(ctx, "DELETE FROM hanko_sessions WHERE scope=$1 AND id=$2", scope, id)
	if err != nil {
		return &SessionError{Category: SessionUnavailable}
	}
	return nil
}
