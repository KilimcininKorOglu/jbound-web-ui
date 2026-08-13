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

	"unbound-web/internal/transport"
)

// Defaults for a new server. They match a Debian install, which is what the
// reference project assumes, and every one of them is editable.
const (
	DefaultHostEntriesPath = "/etc/unbound/host_entries.conf"
	DefaultReloadCmd       = "sudo /usr/sbin/service unbound reload"
	DefaultStatusCmd       = "systemctl is-active unbound"
	DefaultBase64Path      = "/usr/bin/base64"
	DefaultTeePath         = "/usr/bin/tee"
	DefaultMvPath          = "/bin/mv"
	DefaultSha256Path      = "/usr/bin/sha256sum"
	DefaultSSHPort         = 22
)

// TransportSSH is the only transport version one speaks.
const TransportSSH = "ssh"

// Server is one managed DNS server.
type Server struct {
	ID        int64
	Name      string
	Host      string
	SSHPort   int
	Transport string
	SSHUser   string

	// SSHKeyPath is relative to the data directory, so moving the data
	// directory does not invalidate every record.
	SSHKeyPath string

	// HostKey is the approved key in authorized_keys form. Empty means no
	// operator has approved a fingerprint yet.
	HostKey string

	HostEntriesPath string
	ReloadCmd       string
	StatusCmd       string
	Base64Path      string
	TeePath         string
	MvPath          string
	Sha256Path      string

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
	if s.SSHPort == 0 {
		s.SSHPort = DefaultSSHPort
	}
	if s.Transport == "" {
		s.Transport = TransportSSH
	}

	for field, value := range map[*string]string{
		&s.HostEntriesPath: DefaultHostEntriesPath,
		&s.ReloadCmd:       DefaultReloadCmd,
		&s.StatusCmd:       DefaultStatusCmd,
		&s.Base64Path:      DefaultBase64Path,
		&s.TeePath:         DefaultTeePath,
		&s.MvPath:          DefaultMvPath,
		&s.Sha256Path:      DefaultSha256Path,
	} {
		if strings.TrimSpace(*field) == "" {
			*field = value
		}
	}
}

// Validate reports every problem in one pass.
//
// The command and path fields go through the same metacharacter check the
// transport applies, so a record that would inject a second command is refused
// where the operator can still see the form.
func (s Server) Validate() error {
	var problems []string

	if !namePattern.MatchString(s.Name) {
		problems = append(problems,
			"name must start with a letter or digit and may hold letters, digits, dot, dash and underscore")
	}
	if !hostPattern.MatchString(s.Host) {
		problems = append(problems, "host is not a valid host name or address")
	}
	if s.SSHUser == "" {
		problems = append(problems, "ssh user is empty")
	}
	if s.Transport != TransportSSH {
		problems = append(problems, "transport must be "+TransportSSH)
	}
	if s.SSHKeyPath == "" {
		problems = append(problems, "ssh key path is empty")
	}
	if filepath.IsAbs(s.SSHKeyPath) || strings.Contains(s.SSHKeyPath, "..") {
		// The stored path is joined onto the data directory. An absolute path
		// or a parent reference would read a key from anywhere on the host.
		problems = append(problems, "ssh key path must stay inside the data directory")
	}

	// Reuse the transport rules for the remote fields. One definition means
	// the form and the connection can never disagree about what is allowed.
	probe := transport.Config{
		Host:            valueOr(s.Host, "placeholder"),
		Port:            s.SSHPort,
		User:            valueOr(s.SSHUser, "placeholder"),
		KeyPath:         "/placeholder",
		HostEntriesPath: s.HostEntriesPath,
		ReloadCmd:       s.ReloadCmd,
		StatusCmd:       s.StatusCmd,
		Base64Path:      s.Base64Path,
		TeePath:         s.TeePath,
		MvPath:          s.MvPath,
		Sha256Path:      s.Sha256Path,
	}
	if err := probe.Validate(); err != nil {
		problems = append(problems, strings.TrimPrefix(err.Error(), "invalid server configuration: "))
	}

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
	return transport.Config{
		ID:              s.ID,
		Name:            s.Name,
		Host:            s.Host,
		Port:            s.SSHPort,
		User:            s.SSHUser,
		KeyPath:         filepath.Join(dataDir, s.SSHKeyPath),
		HostKey:         s.HostKey,
		HostEntriesPath: s.HostEntriesPath,
		ReloadCmd:       s.ReloadCmd,
		StatusCmd:       s.StatusCmd,
		Base64Path:      s.Base64Path,
		TeePath:         s.TeePath,
		MvPath:          s.MvPath,
		Sha256Path:      s.Sha256Path,
		ConnectTimeout:  connectTimeout,
		CommandTimeout:  commandTimeout,
	}
}
