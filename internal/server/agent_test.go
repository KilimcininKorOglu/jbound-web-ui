package server

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jbound/internal/audit"
	"jbound/internal/transport"
)

// agentInput is a server the panel will reach through an agent.
func agentInput(name string) CreateInput {
	return CreateInput{Server: Server{
		Name: name, Host: name + ".example", Transport: TransportAgent, Enabled: true,
	}}
}

func TestAnAgentServerIsGivenATokenInsteadOfAKeyPair(t *testing.T) {
	// The two are the same act: the panel keeps one copy and the operator
	// installs the other on the target. What differs is the shape.
	h := newHarness(t)

	record, secret, err := h.service.Create(context.Background(), testActor(), agentInput("dns4"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	if record.SSHKeyPath != TokenRelPath(record.ID) {
		t.Errorf("secret path = %q, want the token named after the record", record.SSHKeyPath)
	}
	if strings.HasPrefix(secret.PublicKey, "ssh-") {
		t.Errorf("an agent server was given an ssh key: %q", secret.PublicKey)
	}
	if len(secret.PublicKey) < 32 {
		t.Errorf("the token is %d characters, too short to be one", len(secret.PublicKey))
	}
	if _, err := base64.RawURLEncoding.DecodeString(secret.PublicKey); err != nil {
		t.Errorf("the token is not a value that survives a header: %v", err)
	}
}

func TestATokenIsWrittenWhereOnlyThePanelCanReadIt(t *testing.T) {
	// It is the one secret that reaches a managed server, so it gets the
	// treatment the private keys get: 0600 inside a 0700 directory, and never
	// a row in the database.
	h := newHarness(t)

	record, _, err := h.service.Create(context.Background(), testActor(), agentInput("dns4"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	path := filepath.Join(h.dataDir, record.SSHKeyPath)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the token file is missing: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the token file is mode %o, want 0600", mode)
	}
	if filepath.Dir(path) != h.keys.Dir() {
		t.Errorf("the token sits in %s, outside the key directory", filepath.Dir(path))
	}
}

func TestATokenIsNeverHandedOutASecondTime(t *testing.T) {
	// The public key page re-reads a key on demand, which is safe because a
	// public key is public. Doing the same for a token would turn a page
	// anybody with access can open into a way to collect the credentials of
	// the whole fleet.
	h := newHarness(t)

	record, secret, err := h.service.Create(context.Background(), testActor(), agentInput("dns4"))
	if err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	again, err := h.service.PublicKey(context.Background(), record.ID)
	if err == nil {
		t.Fatalf("the panel handed out %q a second time", again.PublicKey)
	}
	if strings.Contains(err.Error(), secret.PublicKey) {
		t.Errorf("the refusal carries the token: %v", err)
	}

	// The class matters as much as the refusal. Without a guard the panel
	// would still fail, but only because a token does not parse as a private
	// key, which is an accident of the file format rather than a decision. A
	// token that happened to parse would be handed out.
	if !errors.Is(err, ErrValidation) {
		t.Errorf("the refusal is %v, want a decision rather than a parse failure", err)
	}
}

func TestAnAgentServerNeedsNoAccountAndNoCommands(t *testing.T) {
	// Nothing logs in and no command text travels, so asking the operator for
	// an ssh user, tool paths and a reload command would be asking them to
	// fill in fields that reach nothing.
	record := agentInput("dns4").Server
	record.ApplyDefaults()

	if err := record.ValidateInput(); err != nil {
		t.Fatalf("an agent server was refused: %v", err)
	}
	if record.ReloadCmd != "" || record.Base64Path != "" || record.RecordsPath != "" {
		t.Errorf("an agent record was filled with ssh defaults: %+v", record)
	}
	if record.AgentPort != DefaultAgentPort {
		t.Errorf("agent port = %d, want the default", record.AgentPort)
	}
}

func TestATransportThePanelCannotSpeakIsRefused(t *testing.T) {
	record := agentInput("dns4").Server
	record.ApplyDefaults()
	record.Transport = "carrier-pigeon"

	if err := record.ValidateInput(); err == nil {
		t.Fatal("a transport the panel cannot speak was accepted")
	}
}

func TestAnAgentRecordBuildsAnAgentConnection(t *testing.T) {
	// The one field that decides everything downstream. A record that built an
	// ssh configuration would have the pool open a session to sshd on a host
	// that runs none.
	record := Server{
		ID: 4, Name: "dns4", Host: "dns4.example", Transport: TransportAgent,
		AgentPort: 9443, SSHKeyPath: TokenRelPath(4),
		HostKey: "SHA256:abc",
	}

	cfg := record.TransportConfig("/var/lib/jbound", time.Second, time.Second)
	if cfg.Kind != transport.KindAgent {
		t.Errorf("kind = %q", cfg.Kind)
	}
	if cfg.AgentPort != 9443 {
		t.Errorf("agent port = %d", cfg.AgentPort)
	}
	if cfg.TokenPath != filepath.Join("/var/lib/jbound", TokenRelPath(4)) {
		t.Errorf("token path = %q", cfg.TokenPath)
	}

	// Nothing that would become a command on the far end travels with it.
	if cfg.ReloadCmd != "" || cfg.Base64Path != "" || cfg.RecordsPath != "" {
		t.Errorf("an agent configuration carries ssh fields: %+v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("the configuration it built is one it refuses: %v", err)
	}
}

func TestAnAgentServerIsWrittenDownByHowItIsReached(t *testing.T) {
	// The audit row of an ssh server names the account it logs in as. An agent
	// server has none, so a row saying "@dns4.example:22" would name a
	// connection nobody makes.
	h := newHarness(t)

	if _, _, err := h.service.Create(context.Background(), testActor(),
		agentInput("dns4")); err != nil {
		t.Fatalf("Create returned an error: %v", err)
	}

	details := h.auditLog.entries[0].Details
	if h.auditLog.entries[0].Action != audit.ActionServerCreate {
		t.Fatalf("audit actions = %v", h.auditLog.actions())
	}
	if !strings.Contains(details, "agent at dns4.example:8443") {
		t.Errorf("the audit detail does not name the endpoint: %q", details)
	}
	if strings.Contains(details, "@") {
		t.Errorf("the audit detail names an account nobody logs in as: %q", details)
	}
}

func TestATamperedTokenPathIsRefused(t *testing.T) {
	// The path is read back out of the database. A row somebody edited must
	// not be able to point the panel at a file outside the key directory.
	h := newHarness(t)

	for _, relPath := range []string{
		"../../etc/shadow",
		"/etc/shadow",
		"keys/nested/1.token",
	} {
		if _, err := h.keys.TokenPath(relPath); err == nil {
			t.Errorf("TokenPath accepted %q", relPath)
		}
	}
}

func TestAServerWithNoTokenIsSaidSoRatherThanReadAsEmpty(t *testing.T) {
	// An empty path resolves to the key directory itself, and reading that
	// would fail somewhere further along with a message about a directory.
	h := newHarness(t)

	if _, err := h.keys.TokenPath(""); err == nil {
		t.Fatal("TokenPath accepted an empty path")
	}
}

func TestTwoTokensAreNeverTheSame(t *testing.T) {
	// A token generated from a predictable source would be one an attacker can
	// produce, and the fleet is only as safe as the least surprising of them.
	h := newHarness(t)

	seen := map[string]bool{}
	for id := int64(1); id <= 20; id++ {
		token, _, err := h.keys.GenerateToken(id)
		if err != nil {
			t.Fatalf("GenerateToken returned an error: %v", err)
		}
		if seen[token] {
			t.Fatalf("token %d repeats an earlier one", id)
		}
		seen[token] = true
	}
}
