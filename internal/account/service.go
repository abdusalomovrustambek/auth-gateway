package account

import (
	"context"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"
)

// Rules for accounts and lockout.
const (
	MinPasswordLen = 10
	maxPasswordLen = 256
	maxNameLen     = 100
	maxEmailLen    = 254

	maxFailedLogins = 5
	lockDuration    = 15 * time.Minute
)

// InvalidInputError is a registration value the caller must change. Message is
// safe to show to the client.
type InvalidInputError struct {
	Message string
}

func (e *InvalidInputError) Error() string { return e.Message }

// Service holds the account rules. It knows nothing about HTTP.
type Service struct {
	store *Store
	log   *slog.Logger
	now   func() time.Time

	// dummyHash is verified when the email is unknown, so that a login for a
	// missing account takes about as long as one with a wrong password.
	dummyHash string
}

// NewService returns a Service on store that logs events to log.
func NewService(store *Store, log *slog.Logger) (*Service, error) {
	dummy, err := HashPassword("timing-equaliser-not-a-real-password")
	if err != nil {
		return nil, fmt.Errorf("make dummy hash: %w", err)
	}
	return &Service{store: store, log: log, now: time.Now, dummyHash: dummy}, nil
}

// NormalizeEmail trims spaces and lower-cases an email.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// Register creates an account. The email is trimmed and lower-cased; the
// password needs at least MinPasswordLen characters and the name must not be
// empty. A taken email gives ErrDuplicateEmail.
func (s *Service) Register(ctx context.Context, email, password, name string) (User, error) {
	email = NormalizeEmail(email)
	name = strings.TrimSpace(name)
	if err := validate(email, password, name); err != nil {
		return User{}, err
	}

	hash, err := HashPassword(password)
	if err != nil {
		return User{}, fmt.Errorf("hash password: %w", err)
	}
	user, err := s.store.Create(ctx, email, hash, name)
	if err != nil {
		return User{}, fmt.Errorf("create user: %w", err)
	}
	s.log.Info("user registered", "user_id", user.ID)
	return user, nil
}

// Get returns the user with the id, or ErrNotFound.
func (s *Service) Get(ctx context.Context, id string) (User, error) {
	return s.store.ByID(ctx, id)
}

func validate(email, password, name string) error {
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || len(email) > maxEmailLen {
		return &InvalidInputError{"a valid email is required"}
	}
	if n := utf8.RuneCountInString(password); n < MinPasswordLen {
		return &InvalidInputError{fmt.Sprintf("password must be at least %d characters", MinPasswordLen)}
	}
	if len(password) > maxPasswordLen {
		return &InvalidInputError{fmt.Sprintf("password must be at most %d bytes", maxPasswordLen)}
	}
	if name == "" {
		return &InvalidInputError{"name is required"}
	}
	if utf8.RuneCountInString(name) > maxNameLen {
		return &InvalidInputError{fmt.Sprintf("name must be at most %d characters", maxNameLen)}
	}
	return nil
}

