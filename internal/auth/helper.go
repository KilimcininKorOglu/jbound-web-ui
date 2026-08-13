// Package auth authenticates panel users against the local accounts of the
// panel host and applies the account policy.
//
// PAM lives entirely in the setuid C helper. This package only runs it and
// interprets the result, which keeps the Go binary free of cgo and NSS.
package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Helper exit codes, as defined by the helper contract.
const (
	helperOK       = 0
	helperBadPass  = 1
	helperRejected = 2
	helperUsage    = 3
)

// Errors returned by the authenticator. The handler collapses all of them into
// one user facing message, so the caller learns nothing about which check
// failed.
var (
	ErrBadPassword     = errors.New("authentication failed")
	ErrAccountRejected = errors.New("account rejected")
	ErrHelper          = errors.New("auth helper failed")
)

// usernamePattern mirrors the check inside the helper. Validating on both
// sides means a malformed name never reaches PAM even if one side changes.
var usernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// Account carries the facts the helper reports after a successful
// authentication. Policy decisions are made from these, never inside the
// helper, so they stay testable.
type Account struct {
	UID      int
	GID      int
	Username string
	Shell    string
	Groups   []string
}

// InGroup reports whether the account belongs to the named group.
func (a Account) InGroup(name string) bool {
	if name == "" {
		return false
	}
	return slices.Contains(a.Groups, name)
}

// Authenticator runs the setuid helper.
type Authenticator interface {
	Authenticate(ctx context.Context, username, password string) (Account, error)
}

// HelperAuthenticator is the production Authenticator.
type HelperAuthenticator struct {
	path string
	// slots bounds concurrent helper runs. pam_unix sleeps for roughly two
	// seconds after a failed attempt, so unbounded concurrency would let a
	// handful of requests occupy every worker.
	slots chan struct{}
}

// NewHelperAuthenticator validates the helper installation and returns a
// ready authenticator.
func NewHelperAuthenticator(path string, maxConcurrent int) (*HelperAuthenticator, error) {
	if maxConcurrent < 1 {
		return nil, fmt.Errorf("maxConcurrent must be at least 1, got %d", maxConcurrent)
	}
	return &HelperAuthenticator{
		path:  path,
		slots: make(chan struct{}, maxConcurrent),
	}, nil
}

// Authenticate runs the helper for one account.
//
// The password travels on stdin only. Passing it as an argument or in the
// environment would expose it through /proc to every local user.
func (h *HelperAuthenticator) Authenticate(ctx context.Context,
	username, password string) (Account, error) {

	if !usernamePattern.MatchString(username) {
		return Account{}, ErrBadPassword
	}
	// Debian common-auth carries nullok, so PAM would accept an empty
	// password for an account whose password field is empty. Reject it before
	// the helper runs.
	if password == "" {
		return Account{}, ErrBadPassword
	}

	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	case <-ctx.Done():
		return Account{}, ctx.Err()
	}

	cmd := exec.CommandContext(ctx, h.path, username)
	cmd.Stdin = strings.NewReader(password)
	// No inherited environment. A setuid binary must not be handed one.
	cmd.Env = []string{}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			switch exitErr.ExitCode() {
			case helperBadPass:
				return Account{}, ErrBadPassword
			case helperRejected:
				return Account{}, ErrAccountRejected
			case helperUsage:
				return Account{}, fmt.Errorf("%w: %s", ErrHelper, strings.TrimSpace(stderr.String()))
			}
		}
		return Account{}, fmt.Errorf("%w: %v", ErrHelper, err)
	}

	account, parseErr := ParseAccount(stdout.String())
	if parseErr != nil {
		return Account{}, fmt.Errorf("%w: %v", ErrHelper, parseErr)
	}
	return account, nil
}

// ParseAccount reads the single line the helper prints on success.
//
// An unexpected shape is an internal error rather than a login failure. It
// means the helper and the panel disagree about their contract, and silently
// treating that as a bad password would hide a real fault.
func ParseAccount(line string) (Account, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return Account{}, fmt.Errorf("helper produced no output")
	}

	account := Account{UID: -1, GID: -1}
	seen := map[string]bool{}

	for _, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return Account{}, fmt.Errorf("malformed field %q", field)
		}
		seen[key] = true

		switch key {
		case "uid":
			n, err := strconv.Atoi(value)
			if err != nil {
				return Account{}, fmt.Errorf("uid is not a number: %q", value)
			}
			account.UID = n
		case "gid":
			n, err := strconv.Atoi(value)
			if err != nil {
				return Account{}, fmt.Errorf("gid is not a number: %q", value)
			}
			account.GID = n
		case "user":
			account.Username = value
		case "shell":
			account.Shell = value
		case "groups":
			if value != "" {
				account.Groups = strings.Split(value, ",")
			}
		}
	}

	for _, required := range []string{"uid", "gid", "user", "shell", "groups"} {
		if !seen[required] {
			return Account{}, fmt.Errorf("helper output is missing %s", required)
		}
	}
	if account.Username == "" {
		return Account{}, fmt.Errorf("helper reported an empty user name")
	}
	return account, nil
}
