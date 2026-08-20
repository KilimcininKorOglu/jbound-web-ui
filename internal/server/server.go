// Package server manages the DNS servers the panel talks to.
//
// A server record holds everything needed to reach one host: where it is, how
// to authenticate, and which paths and commands that distribution uses. The
// private key is the one thing that never enters the record, because a
// database leak must not hand over the fleet.
package server

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"jbound/internal/transport"
)

// Defaults for a new server. They match a Debian install and every one of
// them is editable.
const (
	DefaultRecordsPath = "/etc/unbound/local_records.conf"

	// The three rungs of a reload, in the order they are tried. The first one
	// preserves the resolver cache, which is the whole reason it comes first:
	// a fleet that drops its cache on every record change answers slowly for
	// as long as it takes to fill again.
	DefaultReloadCmd         = "sudo /usr/sbin/unbound-control reload_keep_cache"
	DefaultReloadFallbackCmd = "sudo /usr/sbin/service unbound reload"
	DefaultRestartCmd        = "sudo /usr/sbin/service unbound restart"

	// The included file sits inside a server clause and cannot be validated on
	// its own, so the check names the main configuration file.
	DefaultCheckConfCmd = "sudo /usr/sbin/unbound-checkconf /etc/unbound/unbound.conf"

	// The command that makes the resolver read the records file. It carries no
	// arguments on purpose: the setup script writes both paths into it on the
	// target, so the panel never names a file the target then writes.
	DefaultEnsureIncludeCmd = "sudo /usr/local/sbin/jbound-ensure-include"

	DefaultStatusCmd  = "systemctl is-active unbound"
	DefaultBase64Path = "/usr/bin/base64"
	DefaultTeePath    = "/usr/bin/tee"
	DefaultMvPath     = "/bin/mv"
	DefaultSha256Path = "/usr/bin/sha256sum"
	DefaultSSHPort    = 22
)

// The two ways the panel reaches a server.
//
// TransportSSH sends command text through a login shell and is held safe by
// exact sudoers rules on the target. TransportAgent sends none at all: the
// panel names a step, and the agent runs whatever its own configuration says
// that step is.
const (
	TransportSSH   = transport.KindSSH
	TransportAgent = transport.KindAgent
)

// DefaultAgentPort is where an agent listens unless the operator moves it.
const DefaultAgentPort = 8443

// Server is one managed DNS server.
type Server struct {
	ID        int64
	Name      string
	Host      string
	SSHPort   int
	Transport string
	SSHUser   string

	// SSHKeyPath is relative to the data directory, so moving the data
	// directory does not invalidate every record. On an agent server it holds
	// the token file instead of a private key, for the same reason and with
	// the same boundary check.
	SSHKeyPath string

	// AgentPort is where the agent listens. It is ignored on an ssh server.
	AgentPort int

	// HostKey is the approved key in authorized_keys form. Empty means no
	// operator has approved a fingerprint yet.
	HostKey string

	RecordsPath string
	ReloadCmd   string
	StatusCmd   string
	Base64Path  string
	TeePath     string
	MvPath      string
	Sha256Path  string

	// CheckConfCmd validates the resolver configuration after a write. An
	// empty command skips the check, which is a target whose sudoers rules
	// have not been extended yet.
	CheckConfCmd string

	// ReloadFallbackCmd and RestartCmd are the second and third rungs of a
	// reload. An empty command skips that rung.
	ReloadFallbackCmd string
	RestartCmd        string

	// EnsureIncludeCmd repairs a main configuration that does not include the
	// records file. An empty command skips the repair, which is a target
	// prepared before this command existed.
	EnsureIncludeCmd string

	// GroupID is the group this server belongs to. Zero means none, and an
	// ungrouped server can only be reached by naming it on its own.
	GroupID int64

	Enabled    bool
	LastSeenAt *time.Time
	LastError  string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Trusted reports whether an operator has approved the host key.
func (s Server) Trusted() bool { return strings.TrimSpace(s.HostKey) != "" }

// namePattern keeps server names usable in a URL and readable in a log line.
var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// hostPattern accepts a host name or an IP address.
var hostPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.:_-]{0,253}[A-Za-z0-9])?$`)

// ApplyDefaults fills the fields the operator left empty.
func (s *Server) ApplyDefaults() {
	// Both ports are filled whichever transport this is, the same way ssh_port
	// carries 22 on an agent server. One of the two is unused rather than
	// wrong, and a record where either is zero would be refused by the schema
	// for a field the operator was never shown.
	if s.SSHPort == 0 {
		s.SSHPort = DefaultSSHPort
	}
	if s.AgentPort == 0 {
		s.AgentPort = DefaultAgentPort
	}
	if s.Transport == "" {
		s.Transport = TransportSSH
	}
	if s.Transport == TransportAgent {
		// Nothing else is filled in. Every remaining field names a path or a
		// command on the target, and on this transport the target owns both.
		// Filling them would put values in front of the operator that reach
		// nothing.
		return
	}

	for field, value := range map[*string]string{
		&s.RecordsPath:       DefaultRecordsPath,
		&s.ReloadCmd:         DefaultReloadCmd,
		&s.StatusCmd:         DefaultStatusCmd,
		&s.Base64Path:        DefaultBase64Path,
		&s.TeePath:           DefaultTeePath,
		&s.MvPath:            DefaultMvPath,
		&s.Sha256Path:        DefaultSha256Path,
		&s.CheckConfCmd:      DefaultCheckConfCmd,
		&s.ReloadFallbackCmd: DefaultReloadFallbackCmd,
		&s.RestartCmd:        DefaultRestartCmd,
		&s.EnsureIncludeCmd:  DefaultEnsureIncludeCmd,
	} {
		if strings.TrimSpace(*field) == "" {
			*field = value
		}
	}
}

// Validate reports every problem of a complete record in one pass.
func (s Server) Validate() error {
	problems := s.inputProblems()

	if s.SSHKeyPath == "" {
		problems = append(problems, "ssh key path is empty")
	}
	return joinProblems(problems)
}

// ValidateInput reports every problem of the operator supplied fields.
//
// The key path is not among them. It is named after the row identifier, so it
// is assigned once the record exists and never comes from a form.
func (s Server) ValidateInput() error {
	return joinProblems(s.inputProblems())
}

// inputProblems collects what is wrong with the fields a person can type.
//
// The command and path fields go through the same metacharacter check the
// transport applies, so a record that would inject a second command is refused
// where the operator can still see the form.
func (s Server) inputProblems() []string {
	var problems []string

	if !namePattern.MatchString(s.Name) {
		problems = append(problems,
			"name must start with a letter or digit and may hold letters, digits, dot, dash and underscore")
	}
	if !hostPattern.MatchString(s.Host) {
		problems = append(problems, "host is not a valid host name or address")
	}
	if s.GroupID < 0 {
		problems = append(problems, "group id is not valid")
	}
	if s.Transport != TransportSSH && s.Transport != TransportAgent {
		problems = append(problems,
			"transport must be "+TransportSSH+" or "+TransportAgent)
	}
	if filepath.IsAbs(s.SSHKeyPath) || strings.Contains(s.SSHKeyPath, "..") {
		// The stored path is joined onto the data directory. An absolute path
		// or a parent reference would read a secret from anywhere on the host.
		problems = append(problems, "key path must stay inside the data directory")
	}

	// Reuse the transport rules for the remote fields. One definition means
	// the form and the connection can never disagree about what is allowed.
	probe := s.probeConfig()
	if err := probe.Validate(); err != nil {
		problems = append(problems, strings.TrimPrefix(err.Error(), "invalid server configuration: "))
	}
	return append(problems, s.transportProblems()...)
}

// transportProblems collects what only one of the two transports asks for.
func (s Server) transportProblems() []string {
	if s.Transport == TransportAgent {
		// An agent server needs no account. Nothing logs in.
		return nil
	}
	if s.SSHUser == "" {
		return []string{"ssh user is empty"}
	}
	return nil
}

// probeConfig builds the configuration the transport rules are checked against.
//
// The placeholders stand in for fields the form does not carry, so a record
// that is otherwise fine is not reported as broken for a value the operator
// never sees.
func (s Server) probeConfig() transport.Config {
	if s.Transport == TransportAgent {
		return transport.Config{
			Kind:      TransportAgent,
			Host:      valueOr(s.Host, "placeholder"),
			AgentPort: s.AgentPort,
			TokenPath: "/placeholder",
		}
	}
	return transport.Config{
		Host:        valueOr(s.Host, "placeholder"),
		Port:        s.SSHPort,
		User:        valueOr(s.SSHUser, "placeholder"),
		KeyPath:     "/placeholder",
		RecordsPath: s.RecordsPath,
		ReloadCmd:   s.ReloadCmd,
		StatusCmd:   s.StatusCmd,
		Base64Path:  s.Base64Path,
		TeePath:     s.TeePath,
		MvPath:      s.MvPath,
		Sha256Path:  s.Sha256Path,

		CheckConfCmd:      s.CheckConfCmd,
		ReloadFallbackCmd: s.ReloadFallbackCmd,
		RestartCmd:        s.RestartCmd,
		EnsureIncludeCmd:  s.EnsureIncludeCmd,
	}
}

func joinProblems(problems []string) error {
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// TransportConfig turns a record into the configuration the transport needs.
//
// dataDir resolves the key path, which is stored relative so the data
// directory can move.
func (s Server) TransportConfig(dataDir string, connectTimeout, commandTimeout time.Duration) transport.Config {
	if s.Transport == TransportAgent {
		return transport.Config{
			ID:        s.ID,
			Name:      s.Name,
			Kind:      TransportAgent,
			Host:      s.Host,
			AgentPort: s.AgentPort,
			HostKey:   s.HostKey,

			// The same column holds the token file here that holds the private
			// key on the other transport, and the same boundary check applies
			// to both.
			TokenPath: filepath.Join(dataDir, s.SSHKeyPath),

			ConnectTimeout: connectTimeout,
			CommandTimeout: commandTimeout,
		}
	}

	return transport.Config{
		ID:          s.ID,
		Name:        s.Name,
		Kind:        TransportSSH,
		Host:        s.Host,
		Port:        s.SSHPort,
		User:        s.SSHUser,
		KeyPath:     filepath.Join(dataDir, s.SSHKeyPath),
		HostKey:     s.HostKey,
		RecordsPath: s.RecordsPath,
		ReloadCmd:   s.ReloadCmd,
		StatusCmd:   s.StatusCmd,
		Base64Path:  s.Base64Path,
		TeePath:     s.TeePath,
		MvPath:      s.MvPath,
		Sha256Path:  s.Sha256Path,

		CheckConfCmd:      s.CheckConfCmd,
		ReloadFallbackCmd: s.ReloadFallbackCmd,
		RestartCmd:        s.RestartCmd,
		EnsureIncludeCmd:  s.EnsureIncludeCmd,

		ConnectTimeout: connectTimeout,
		CommandTimeout: commandTimeout,
	}
}
