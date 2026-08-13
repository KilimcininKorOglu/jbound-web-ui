package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// Roles recognised by the panel.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// deniedShells reject an account even when PAM accepted the password. Service
// accounts carry these shells, and none of them should reach the panel.
var deniedShells = map[string]bool{
	"/usr/sbin/nologin": true,
	"/sbin/nologin":     true,
	"/bin/false":        true,
	"/usr/bin/false":    true,
}

// Policy decides whether an authenticated account may use the panel and which
// role it gets.
//
// PAM answers "is this the right password for a valid account". It does not
// answer "should this account administer DNS", which is what these rules add.
type Policy struct {
	MinUID       int
	AdminGroup   string
	AllowedGroup string
}

// User is an accepted account together with its role.
type User struct {
	Account
	Role string
}

// IsAdmin reports whether the user may reach the admin only areas.
func (u User) IsAdmin() bool { return u.Role == RoleAdmin }

// Apply runs the account policy.
//
// The returned error names the failed rule for the server log. The handler
// never shows it to the user, because naming the rule would confirm that the
// account exists.
func (p Policy) Apply(account Account) (User, error) {
	if account.UID != 0 && account.UID < p.MinUID {
		return User{}, fmt.Errorf("uid %d is below MIN_UID %d", account.UID, p.MinUID)
	}
	if deniedShells[account.Shell] {
		return User{}, fmt.Errorf("shell %s is on the denied list", account.Shell)
	}
	if p.AllowedGroup != "" && !account.InGroup(p.AllowedGroup) {
		return User{}, fmt.Errorf("account is not a member of ALLOWED_GROUP %s", p.AllowedGroup)
	}

	role := RoleUser
	// uid 0 is admin regardless of group membership, because root already
	// controls the machine the panel runs on.
	if account.UID == 0 || account.InGroup(p.AdminGroup) {
		role = RoleAdmin
	}
	return User{Account: account, Role: role}, nil
}

// Service ties the helper and the policy together.
type Service struct {
	auth   Authenticator
	policy Policy
}

// NewService builds the authentication service.
func NewService(auth Authenticator, policy Policy) *Service {
	return &Service{auth: auth, policy: policy}
}

// ErrLoginFailed is the single failure every rejected login produces.
//
// One message covers every failure, so the login form cannot tell an attacker
// which accounts exist, which are locked, and which are merely wrong.
var ErrLoginFailed = errors.New("invalid username or password")

// Login authenticates a user and applies the policy.
func (s *Service) Login(ctx context.Context, username, password string) (User, error) {
	account, err := s.auth.Authenticate(ctx, username, password)
	if err != nil {
		switch {
		case errors.Is(err, ErrBadPassword):
			slog.Info("login rejected", "username", username, "reason", "bad password")
		case errors.Is(err, ErrAccountRejected):
			slog.Info("login rejected", "username", username, "reason", "account rejected by PAM")
		case errors.Is(err, ErrHelper):
			// A broken helper is an operational fault, not a login attempt.
			slog.Error("auth helper failed", "username", username, "error", err)
		default:
			return User{}, err
		}
		return User{}, ErrLoginFailed
	}

	user, err := s.policy.Apply(account)
	if err != nil {
		slog.Info("login rejected", "username", username, "reason", err.Error())
		return User{}, ErrLoginFailed
	}
	return user, nil
}
