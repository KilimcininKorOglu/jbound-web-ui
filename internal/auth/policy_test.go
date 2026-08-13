package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func testPolicy() Policy {
	return Policy{MinUID: 1000, AdminGroup: "sudo"}
}

func TestPolicyAcceptsRootAsAdmin(t *testing.T) {
	// uid 0 is admin regardless of group membership, because root already
	// controls the host the panel runs on.
	user, err := testPolicy().Apply(Account{
		UID: 0, GID: 0, Username: "root", Shell: "/bin/bash", Groups: []string{"root"},
	})
	if err != nil {
		t.Fatalf("root was rejected: %v", err)
	}
	if !user.IsAdmin() {
		t.Errorf("root got role %q, want admin", user.Role)
	}
}

func TestPolicyGivesAdminToAdminGroupMembers(t *testing.T) {
	user, err := testPolicy().Apply(Account{
		UID: 1001, GID: 1001, Username: "dnsadmin", Shell: "/bin/bash",
		Groups: []string{"dnsadmin", "sudo"},
	})
	if err != nil {
		t.Fatalf("dnsadmin was rejected: %v", err)
	}
	if !user.IsAdmin() {
		t.Errorf("dnsadmin got role %q, want admin", user.Role)
	}
}

func TestPolicyGivesUserRoleToPlainAccounts(t *testing.T) {
	user, err := testPolicy().Apply(Account{
		UID: 1002, GID: 1002, Username: "dnsuser", Shell: "/bin/bash",
		Groups: []string{"dnsuser"},
	})
	if err != nil {
		t.Fatalf("dnsuser was rejected: %v", err)
	}
	if user.Role != RoleUser {
		t.Errorf("dnsuser got role %q, want user", user.Role)
	}
	if user.IsAdmin() {
		t.Error("dnsuser must not be an admin")
	}
}

func TestPolicyRejectsDeniedShells(t *testing.T) {
	// Service accounts carry these shells. PAM happily authenticates them, so
	// this rule is what keeps them out of the panel.
	for _, shell := range []string{
		"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false",
	} {
		t.Run(shell, func(t *testing.T) {
			_, err := testPolicy().Apply(Account{
				UID: 1003, GID: 1003, Username: "svcacct", Shell: shell,
			})
			if err == nil {
				t.Fatalf("an account with shell %s was accepted", shell)
			}
			if !strings.Contains(err.Error(), "shell") {
				t.Errorf("error does not name the shell rule: %v", err)
			}
		})
	}
}

func TestPolicyRejectsUIDBelowMinimum(t *testing.T) {
	_, err := testPolicy().Apply(Account{
		UID: 500, GID: 1004, Username: "lowuid", Shell: "/bin/bash",
	})
	if err == nil {
		t.Fatal("an account below MIN_UID was accepted")
	}
	if !strings.Contains(err.Error(), "MIN_UID") {
		t.Errorf("error does not name the uid rule: %v", err)
	}
}

func TestPolicyEnforcesAllowedGroupWhenConfigured(t *testing.T) {
	policy := Policy{MinUID: 1000, AdminGroup: "sudo", AllowedGroup: "dnsops"}

	if _, err := policy.Apply(Account{
		UID: 1002, Username: "dnsuser", Shell: "/bin/bash", Groups: []string{"dnsuser"},
	}); err == nil {
		t.Error("an account outside ALLOWED_GROUP was accepted")
	}

	if _, err := policy.Apply(Account{
		UID: 1002, Username: "dnsuser", Shell: "/bin/bash",
		Groups: []string{"dnsuser", "dnsops"},
	}); err != nil {
		t.Errorf("a member of ALLOWED_GROUP was rejected: %v", err)
	}
}

func TestPolicySkipsAllowedGroupWhenEmpty(t *testing.T) {
	if _, err := testPolicy().Apply(Account{
		UID: 1002, Username: "dnsuser", Shell: "/bin/bash", Groups: []string{"dnsuser"},
	}); err != nil {
		t.Errorf("the empty ALLOWED_GROUP was treated as a filter: %v", err)
	}
}

// --- Service ---------------------------------------------------------------

type stubAuthenticator struct {
	account Account
	err     error
	calls   int
	lastPw  string
}

func (s *stubAuthenticator) Authenticate(_ context.Context, _, password string) (Account, error) {
	s.calls++
	s.lastPw = password
	return s.account, s.err
}

func TestServiceReturnsOneMessageForEveryFailure(t *testing.T) {
	cases := []struct {
		name string
		stub *stubAuthenticator
	}{
		{"bad password", &stubAuthenticator{err: ErrBadPassword}},
		{"account rejected", &stubAuthenticator{err: ErrAccountRejected}},
		{"helper failure", &stubAuthenticator{err: ErrHelper}},
		{"policy rejection", &stubAuthenticator{account: Account{
			UID: 500, Username: "lowuid", Shell: "/bin/bash"}}},
		{"denied shell", &stubAuthenticator{account: Account{
			UID: 1003, Username: "svcacct", Shell: "/usr/sbin/nologin"}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewService(tc.stub, testPolicy())
			_, err := svc.Login(context.Background(), "someone", "secret")
			// Every rejection must look identical from outside, otherwise the
			// login form becomes an account enumeration oracle.
			if !errors.Is(err, ErrLoginFailed) {
				t.Fatalf("got %v, want ErrLoginFailed", err)
			}
		})
	}
}

func TestServiceReturnsTheUserOnSuccess(t *testing.T) {
	stub := &stubAuthenticator{account: Account{
		UID: 1001, GID: 1001, Username: "dnsadmin", Shell: "/bin/bash",
		Groups: []string{"dnsadmin", "sudo"},
	}}
	svc := NewService(stub, testPolicy())

	user, err := svc.Login(context.Background(), "dnsadmin", "secret")
	if err != nil {
		t.Fatalf("Login returned an error: %v", err)
	}
	if user.Username != "dnsadmin" || !user.IsAdmin() {
		t.Errorf("got %+v, want dnsadmin with the admin role", user)
	}
	if stub.lastPw != "secret" {
		t.Errorf("the password reached the authenticator as %q", stub.lastPw)
	}
}
