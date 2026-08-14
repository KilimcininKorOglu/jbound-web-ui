package server

import (
	"strings"
	"testing"
	"time"
)

func validServer() Server {
	record := Server{
		Name:       "dns1",
		Host:       "dns1.example",
		SSHUser:    "dnsops",
		SSHKeyPath: "keys/dns1.key",
	}
	record.ApplyDefaults()
	return record
}

func TestApplyDefaultsFillsTheEmptyFields(t *testing.T) {
	record := Server{Name: "dns1", Host: "dns1.example", SSHUser: "dnsops"}
	record.ApplyDefaults()

	if record.SSHPort != DefaultSSHPort {
		t.Errorf("port = %d, want %d", record.SSHPort, DefaultSSHPort)
	}
	if record.Transport != TransportSSH {
		t.Errorf("transport = %q, want %q", record.Transport, TransportSSH)
	}
	if record.RecordsPath != DefaultRecordsPath {
		t.Errorf("records path = %q", record.RecordsPath)
	}
	if record.Sha256Path != DefaultSha256Path {
		t.Errorf("sha256 path = %q", record.Sha256Path)
	}
}

func TestApplyDefaultsKeepsWhatTheOperatorTyped(t *testing.T) {
	record := Server{
		Name: "dns1", Host: "dns1.example", SSHUser: "dnsops",
		SSHPort:     2222,
		RecordsPath: "/opt/unbound/entries.conf",
	}
	record.ApplyDefaults()

	if record.SSHPort != 2222 {
		t.Errorf("port = %d, want the value that was entered", record.SSHPort)
	}
	if record.RecordsPath != "/opt/unbound/entries.conf" {
		t.Errorf("records path = %q, want the value that was entered", record.RecordsPath)
	}
}

func TestValidateAcceptsAWorkingRecord(t *testing.T) {
	if err := validServer().Validate(); err != nil {
		t.Fatalf("a valid record was refused: %v", err)
	}
}

func TestValidateRefusesABadName(t *testing.T) {
	// The name becomes a file name for the private key, so it stays narrow.
	for _, name := range []string{"", "-leading", "with space", "../escape", "a/b", strings.Repeat("x", 65)} {
		t.Run(name, func(t *testing.T) {
			record := validServer()
			record.Name = name

			if err := record.Validate(); err == nil {
				t.Fatalf("Validate accepted the name %q", name)
			}
		})
	}
}

func TestValidateRefusesAKeyPathOutsideTheDataDirectory(t *testing.T) {
	// The stored path is joined onto the data directory, so an absolute path
	// or a parent reference would read a key from anywhere on the host.
	for _, path := range []string{"/etc/shadow", "../../etc/shadow", "keys/../../secret"} {
		t.Run(path, func(t *testing.T) {
			record := validServer()
			record.SSHKeyPath = path

			err := record.Validate()
			if err == nil {
				t.Fatalf("Validate accepted the key path %q", path)
			}
			if !strings.Contains(err.Error(), "data directory") {
				t.Errorf("the error does not name the rule: %v", err)
			}
		})
	}
}

func TestValidateRefusesShellMetacharactersInTheRemoteFields(t *testing.T) {
	// The form and the transport share one definition of what is allowed, so
	// they cannot drift apart.
	record := validServer()
	record.ReloadCmd = "sudo service unbound reload; id"

	err := record.Validate()
	if err == nil {
		t.Fatal("Validate accepted an injected command")
	}
	if !strings.Contains(err.Error(), "reload command") {
		t.Errorf("the error does not name the field: %v", err)
	}
}

func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	record := validServer()
	record.Name = ""
	record.Host = ""
	record.SSHUser = ""

	err := record.Validate()
	if err == nil {
		t.Fatal("Validate accepted three broken values")
	}
	for _, want := range []string{"name", "host", "ssh user"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %s: %v", want, err)
		}
	}
}

func TestTrustedReportsWhetherAKeyWasApproved(t *testing.T) {
	record := validServer()
	if record.Trusted() {
		t.Error("a record with no host key reports as trusted")
	}

	record.HostKey = "ssh-ed25519 AAAA"
	if !record.Trusted() {
		t.Error("a record with a host key reports as untrusted")
	}
}

func TestTransportConfigResolvesTheKeyAgainstTheDataDirectory(t *testing.T) {
	record := validServer()
	record.ID = 7

	cfg := record.TransportConfig("/var/lib/jbound", time.Second, 2*time.Second)

	if cfg.KeyPath != "/var/lib/jbound/keys/dns1.key" {
		t.Errorf("key path = %q", cfg.KeyPath)
	}
	if cfg.ID != 7 || cfg.Name != "dns1" || cfg.Port != DefaultSSHPort {
		t.Errorf("the record did not reach the configuration: %+v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("the produced configuration is not usable: %v", err)
	}
}

func TestGroupValidateRefusesADuplicateMember(t *testing.T) {
	group := Group{Name: "resolvers", ServerIDs: []int64{1, 2, 1}}

	err := group.Validate()
	if err == nil {
		t.Fatal("Validate accepted a server listed twice")
	}
	if !strings.Contains(err.Error(), "twice") {
		t.Errorf("the error does not name the problem: %v", err)
	}
}

func TestGroupValidateAcceptsAGroupWithNoMembers(t *testing.T) {
	// An empty group is a normal state while it is being built. Targeting one
	// is what gets refused, and that is the job of the service.
	group := Group{Name: "resolvers"}

	if err := group.Validate(); err != nil {
		t.Fatalf("an empty group was refused: %v", err)
	}
}

func TestANewServerCarriesEveryRungOfTheReloadAndTheCheck(t *testing.T) {
	// A record created without them would have no configuration check and no
	// escalation, which is the behaviour these fields exist to replace.
	record := Server{Name: "dns1", Host: "dns1.example", SSHUser: "dnsops"}
	record.ApplyDefaults()

	for name, got := range map[string]string{
		"reload":          record.ReloadCmd,
		"reload fallback": record.ReloadFallbackCmd,
		"restart":         record.RestartCmd,
		"config check":    record.CheckConfCmd,
	} {
		if strings.TrimSpace(got) == "" {
			t.Errorf("the %s command is empty", name)
		}
	}

	// The first rung preserves the cache. A fleet that drops it on every
	// record change answers slowly until it is filled again.
	if !strings.Contains(record.ReloadCmd, "reload_keep_cache") {
		t.Errorf("reload command = %q, want the cache preserved", record.ReloadCmd)
	}
}

func TestTheNewCommandsReachTheTransport(t *testing.T) {
	record := validServer()
	cfg := record.TransportConfig("/var/lib/jbound", time.Second, 2*time.Second)

	if cfg.CheckConfCmd != record.CheckConfCmd ||
		cfg.ReloadFallbackCmd != record.ReloadFallbackCmd ||
		cfg.RestartCmd != record.RestartCmd {
		t.Errorf("the transport config lost a command: %+v", cfg)
	}
}

func TestACommandThatWouldRunASecondCommandIsRefused(t *testing.T) {
	// The new fields reach a remote shell like the old ones, so they go
	// through the same metacharacter check rather than a new one.
	for name, mutate := range map[string]func(*Server){
		"check":    func(s *Server) { s.CheckConfCmd = "sudo unbound-checkconf; rm -rf /" },
		"fallback": func(s *Server) { s.ReloadFallbackCmd = "sudo service unbound reload && id" },
		"restart":  func(s *Server) { s.RestartCmd = "sudo service unbound restart `id`" },
	} {
		t.Run(name, func(t *testing.T) {
			record := validServer()
			mutate(&record)

			if err := record.Validate(); err == nil {
				t.Error("the record was accepted")
			}
		})
	}
}

func TestALadderRungMayBeLeftEmpty(t *testing.T) {
	// A target whose sudoers rules do not name a command yet skips that rung
	// rather than failing every change.
	record := validServer()
	record.CheckConfCmd = ""
	record.ReloadFallbackCmd = ""
	record.RestartCmd = ""

	if err := record.Validate(); err != nil {
		t.Errorf("the record was refused: %v", err)
	}
}
