package account

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrInvalidCredentials is returned for an unknown email and for a wrong
// password alike.
var ErrInvalidCredentials = errors.New("account: invalid email or password")

// LockedError is returned while an account is locked after repeated failures.
type LockedError struct {
	Until time.Time
}

func (e *LockedError) Error() string {
	return "account: locked until " + e.Until.UTC().Format(time.RFC3339)
}

// Login checks the credentials. failed_logins counts consecutive failures: the
// 5th sets locked_until to now + 15 minutes, and while it is in the future
// Login returns *LockedError even for the right password. A success, or a login
// after the lock has expired, resets the counter.
func (s *Service) Login(ctx context.Context, email, password string) (User, error) {
	email = NormalizeEmail(email)

	user, err := s.store.ByEmail(ctx, email)
	if errors.Is(err, ErrNotFound) {
		// Spend the same time as for a wrong password and keep no state.
		if _, err := VerifyPassword(password, s.dummyHash); err != nil {
			return User{}, fmt.Errorf("verify dummy hash: %w", err)
		}
		s.log.Warn("login failed", "reason", "unknown email")
		return User{}, ErrInvalidCredentials
	}
	if err != nil {
		return User{}, fmt.Errorf("load user: %w", err)
	}

	now := s.now()
	if user.LockedUntil != nil {
		if user.LockedUntil.After(now) {
			return User{}, &LockedError{Until: *user.LockedUntil}
		}
		// The lock has run out: start counting again.
		if err := s.store.ResetFailures(ctx, user.ID); err != nil {
			return User{}, err
		}
		user.FailedLogins, user.LockedUntil = 0, nil
	}

	ok, err := VerifyPassword(password, user.PasswordHash)
	if err != nil {
		return User{}, fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		return User{}, s.failed(ctx, user, now)
	}

	if user.FailedLogins > 0 {
		if err := s.store.ResetFailures(ctx, user.ID); err != nil {
			return User{}, err
		}
		user.FailedLogins = 0
	}
	return user, nil
}

// failed records a wrong password and returns ErrInvalidCredentials, or the
// store error if counting failed.
func (s *Service) failed(ctx context.Context, user User, now time.Time) error {
	count, lockedUntil, err := s.store.RecordFailure(ctx, user.ID, maxFailedLogins, now.Add(lockDuration))
	if err != nil {
		return err
	}
	s.log.Warn(fmt.Sprintf("login failed for %s: wrong password", user.Email), "user_id", user.ID, "failed_logins", count)
	if lockedUntil != nil {
		s.log.Warn("account locked", "user_id", user.ID, "locked_until", lockedUntil.UTC().Format(time.RFC3339))
	}
	return ErrInvalidCredentials
}
