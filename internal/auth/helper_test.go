package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAccountReadsTheHelperLine(t *testing.T) {
	account, err := ParseAccount(
		"uid=1001 gid=1001 user=dnsadmin shell=/bin/bash groups=dnsadmin,sudo\n")
	if err != nil {
		t.Fatalf("ParseAccount returned an error: %v", err)
	}
	if account.UID != 1001 || account.GID != 1001 {
		t.Errorf("uid/gid = %d/%d, want 1001/1001", account.UID, account.GID)
	}
	if account.Username != "dnsadmin" {
		t.Errorf("username = %q, want dnsadmin", account.Username)
	}
	if account.Shell != "/bin/bash" {
		t.Errorf("shell = %q, want /bin/bash", account.Shell)
	}
	if !account.InGroup("sudo") {
		t.Errorf("groups = %v, want sudo among them", account.Groups)
	}
}

func TestParseAccountHandlesRootAndEmptyGroups(t *testing.T) {
	account, err := ParseAccount("uid=0 gid=0 user=root shell=/bin/bash groups=")
	if err != nil {
		t.Fatalf("ParseAccount returned an error: %v", err)
	}
	if account.UID != 0 {
		t.Errorf("uid = %d, want 0", account.UID)
	}
	if len(account.Groups) != 0 {
		t.Errorf("groups = %v, want none", account.Groups)
	}
}

// A malformed line means the helper and the panel disagree about their
// contract. Treating that as a bad password would hide a real fault.
func TestParseAccountRejectsMalformedOutput(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"missing uid", "gid=1001 user=x shell=/bin/bash groups=x"},
		{"missing gid", "uid=1001 user=x shell=/bin/bash groups=x"},
		{"missing user", "uid=1001 gid=1001 shell=/bin/bash groups=x"},
		{"missing shell", "uid=1001 gid=1001 user=x groups=x"},
		{"missing groups", "uid=1001 gid=1001 user=x shell=/bin/bash"},
		{"uid not a number", "uid=root gid=1001 user=x shell=/bin/bash groups=x"},
		{"field without a separator", "uid=1001 gid=1001 user=x shell=/bin/bash groups=x extra"},
		{"empty user name", "uid=1001 gid=1001 user= shell=/bin/bash groups=x"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseAccount(tc.in); err == nil {
				t.Fatalf("ParseAccount accepted %q", tc.in)
			}
		})
	}
}

func TestInGroupIgnoresTheEmptyName(t *testing.T) {
	account := Account{Groups: []string{"dnsuser", ""}}
	if account.InGroup("") {
		t.Error("an empty group name matched")
	}
}

func newTestHelper(t *testing.T, script string) *HelperAuthenticator {
	t.Helper()
	path := filepath.Join(t.TempDir(), "helper.sh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("cannot write the stub helper: %v", err)
	}
	auth, err := NewHelperAuthenticator(path, 2)
	if err != nil {
		t.Fatalf("NewHelperAuthenticator failed: %v", err)
	}
	return auth
}

func TestAuthenticateMapsHelperExitCodes(t *testing.T) {
	cases := []struct {
		name string
		code string
		want error
	}{
		{"bad password", "1", ErrBadPassword},
		{"account rejected", "2", ErrAccountRejected},
		{"usage error", "3", ErrHelper},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth := newTestHelper(t, "#!/bin/sh\ncat >/dev/null\nexit "+tc.code+"\n")
			_, err := auth.Authenticate(context.Background(), "dnsuser", "secret")
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAuthenticateRejectsAnEmptyPasswordBeforeRunningTheHelper(t *testing.T) {
	// The helper would exit 0 here. Reaching it at all would mean the nullok
	// option in Debian common-auth decides the outcome.
	auth := newTestHelper(t,
		"#!/bin/sh\ncat >/dev/null\necho 'uid=1006 gid=1006 user=nopwuser shell=/bin/bash groups=nopwuser'\n")

	_, err := auth.Authenticate(context.Background(), "nopwuser", "")
	if !errors.Is(err, ErrBadPassword) {
		t.Fatalf("got %v, want ErrBadPassword", err)
	}
}

func TestAuthenticateRejectsInvalidUsernames(t *testing.T) {
	auth := newTestHelper(t, "#!/bin/sh\nexit 0\n")

	for _, name := range []string{"", "Root", "user name", "-leading", "a;b", strings.Repeat("a", 33)} {
		t.Run(name, func(t *testing.T) {
			if _, err := auth.Authenticate(context.Background(), name, "secret"); !errors.Is(err, ErrBadPassword) {
				t.Fatalf("username %q was not rejected", name)
			}
		})
	}
}

// The password must travel on stdin only. Passing it as an argument or in the
// environment would expose it through /proc to every local account.
func TestAuthenticatePassesThePasswordOnStdinOnly(t *testing.T) {
	auth := newTestHelper(t, `#!/bin/sh
read -r password
if [ "$password" != "s3cr3t" ]; then
  echo "stdin carried $password" >&2
  exit 1
fi
for arg in "$@"; do
  case "$arg" in *s3cr3t*) echo "password in argv" >&2; exit 3;; esac
done
if env | grep -q s3cr3t; then
  echo "password in the environment" >&2
  exit 3
fi
echo "uid=1002 gid=1002 user=dnsuser shell=/bin/bash groups=dnsuser"
`)

	account, err := auth.Authenticate(context.Background(), "dnsuser", "s3cr3t")
	if err != nil {
		t.Fatalf("Authenticate returned an error: %v", err)
	}
	if account.Username != "dnsuser" {
		t.Errorf("username = %q, want dnsuser", account.Username)
	}
}

func TestAuthenticateRejectsAnUnparsableSuccessLine(t *testing.T) {
	auth := newTestHelper(t, "#!/bin/sh\ncat >/dev/null\necho 'all good'\n")

	_, err := auth.Authenticate(context.Background(), "dnsuser", "secret")
	if !errors.Is(err, ErrHelper) {
		t.Fatalf("got %v, want ErrHelper", err)
	}
}

func TestNewHelperAuthenticatorRejectsZeroConcurrency(t *testing.T) {
	if _, err := NewHelperAuthenticator("/bin/true", 0); err == nil {
		t.Error("a concurrency limit of zero was accepted")
	}
}

func TestAuthenticateHonoursContextCancellation(t *testing.T) {
	auth := newTestHelper(t, "#!/bin/sh\nsleep 30\n")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := auth.Authenticate(ctx, "dnsuser", "secret"); err == nil {
		t.Fatal("a cancelled context did not stop the helper")
	}
}
