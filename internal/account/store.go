package account

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Errors returned by Store.
var (
	ErrNotFound       = errors.New("account: user not found")
	ErrDuplicateEmail = errors.New("account: email already registered")
)

// uniqueViolation is the Postgres error code for a unique constraint failure.
const uniqueViolation = "23505"

// invalidText is the Postgres error code for text that is not a valid value of
// its type, such as an id that is not a UUID.
const invalidText = "22P02"

// User is a row of auth.users.
type User struct {
	ID           string
	Email        string
	PasswordHash string
	Name         string
	CreatedAt    time.Time
	FailedLogins int
	LockedUntil  *time.Time
}

// Store reads and writes auth.users. It holds no policy: the Service decides.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store on pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

const userColumns = `id::text, email, password_hash, name, created_at, failed_logins, locked_until`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.CreatedAt, &u.FailedLogins, &u.LockedUntil)
	return u, err
}

// Create inserts a user. A taken email gives ErrDuplicateEmail.
func (s *Store) Create(ctx context.Context, email, passwordHash, name string) (User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING `+userColumns,
		email, passwordHash, name))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return User{}, ErrDuplicateEmail
	}
	if err != nil {
		return User{}, fmt.Errorf("insert user: %w", err)
	}
	return u, nil
}

// ByEmail finds a user by its (already lower-cased) email.
func (s *Store) ByEmail(ctx context.Context, email string) (User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE email = $1`, email))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("load user by email: %w", err)
	}
	return u, nil
}

// ByID finds a user by id. An id that is not a UUID is ErrNotFound too.
func (s *Store) ByID(ctx context.Context, id string) (User, error) {
	u, err := scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1::uuid`, id))
	var pgErr *pgconn.PgError
	if errors.Is(err, pgx.ErrNoRows) || (errors.As(err, &pgErr) && pgErr.Code == invalidText) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("load user by id: %w", err)
	}
	return u, nil
}

// RecordFailure counts one more failed login in a single statement. When the
// count reaches maxFailures, locked_until is set to lockedUntil. It returns the
// new count and the lock time (nil when not locked).
func (s *Store) RecordFailure(ctx context.Context, id string, maxFailures int, lockedUntil time.Time) (int, *time.Time, error) {
	var (
		failed int
		locked *time.Time
	)
	err := s.pool.QueryRow(ctx,
		`UPDATE users
		    SET failed_logins = failed_logins + 1,
		        locked_until  = CASE WHEN failed_logins + 1 >= $2 THEN $3 ELSE locked_until END
		  WHERE id = $1::uuid
		RETURNING failed_logins, locked_until`,
		id, maxFailures, lockedUntil).Scan(&failed, &locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, ErrNotFound
	}
	if err != nil {
		return 0, nil, fmt.Errorf("record failed login: %w", err)
	}
	return failed, locked, nil
}

// ResetFailures clears the failure count and any lock.
func (s *Store) ResetFailures(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1::uuid`, id)
	if err != nil {
		return fmt.Errorf("reset failed logins: %w", err)
	}
	return nil
}
