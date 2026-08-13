package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"unbound-web/internal/audit"
	"unbound-web/internal/transport"
)

// Repository stores the server records.
type Repository interface {
	Create(ctx context.Context, record Server) (Server, error)
	Update(ctx context.Context, record Server) error
	SetKeyPath(ctx context.Context, id int64, relPath string) error
	SetHostKey(ctx context.Context, id int64, hostKey string) error
	SetReachability(ctx context.Context, id int64, at time.Time, failure string) error
	Get(ctx context.Context, id int64) (Server, error)
	List(ctx context.Context) ([]Server, error)
	Delete(ctx context.Context, id int64) error
}

// GroupRepository stores the groups.
type GroupRepository interface {
	Create(ctx context.Context, group Group) (Group, error)
	Update(ctx context.Context, group Group) error
	Get(ctx context.Context, id int64) (Group, error)
	List(ctx context.Context) ([]Group, error)
	Members(ctx context.Context, groupID int64) ([]Server, error)
	Delete(ctx context.Context, id int64) error
}

// Connector opens a transport for one server.
type Connector interface {
	Get(cfg transport.Config) (transport.Transport, error)
	Remove(id int64)
}

// Actor is the signed in user an action is recorded against.
type Actor struct {
	UID       int
	Username  string
	IPAddress string
}

// ErrValidation marks a rejected input, which the handler answers with 422
// rather than 500.
var ErrValidation = errors.New("invalid input")

// ErrNameTaken marks a name that is already in use.
//
// It lives here rather than in the store, because both servers and groups are
// named and the operator has to read the same refusal either way.
var ErrNameTaken = errors.New("the name is already in use")

// Service holds the server and group operations.
type Service struct {
	servers Repository
	groups  GroupRepository
	keys    *KeyStore
	pool    Connector
	audit   *audit.Logger
	dataDir string

	// timeouts is an accessor rather than a value, so a change made on the
	// settings page reaches the next connection attempt.
	timeouts func() Timeouts

	now func() time.Time
}

// Timeouts bounds the connection attempts the service makes.
type Timeouts struct {
	Connect time.Duration
	Command time.Duration
}

// NewService builds the service.
func NewService(servers Repository, groups GroupRepository, keys *KeyStore,
	pool Connector, auditLog *audit.Logger, dataDir string,
	timeouts func() Timeouts) *Service {

	return &Service{
		servers:  servers,
		groups:   groups,
		keys:     keys,
		pool:     pool,
		audit:    auditLog,
		dataDir:  dataDir,
		timeouts: timeouts,
		now:      time.Now,
	}
}

// CreateInput is a new server together with its key choice.
type CreateInput struct {
	Server Server

	// PrivateKey holds a key the operator supplied. Empty means the panel
	// generates one.
	PrivateKey string
}

// Create stores a new server and prepares its key.
//
// The record is written first, because the key file is named after the row
// identifier the database issues. A failure after that point removes the record
// again, so a server never survives without the key it needs to reach anything.
func (s *Service) Create(ctx context.Context, actor Actor, input CreateInput) (Server, KeyPair, error) {
	record := input.Server
	record.ApplyDefaults()

	if err := record.ValidateInput(); err != nil {
		return Server{}, KeyPair{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}

	stored, err := s.servers.Create(ctx, record)
	if err != nil {
		return Server{}, KeyPair{}, err
	}

	pair, err := s.makeKey(stored.ID, input.PrivateKey)
	if err != nil {
		s.discard(ctx, stored.ID, pair.RelPath)
		return Server{}, KeyPair{}, err
	}

	stored.SSHKeyPath = pair.RelPath
	if err := s.servers.SetKeyPath(ctx, stored.ID, pair.RelPath); err != nil {
		s.discard(ctx, stored.ID, pair.RelPath)
		return Server{}, KeyPair{}, err
	}

	s.writeFor(ctx, actor, audit.ActionServerCreate, &stored.ID, stored.Name, fmt.Sprintf(
		"Created server: %s (%s@%s:%d)", stored.Name, stored.SSHUser, stored.Host, stored.SSHPort))

	return stored, pair, nil
}

// makeKey generates a key or stores the one the operator supplied.
func (s *Service) makeKey(id int64, private string) (KeyPair, error) {
	if strings.TrimSpace(private) == "" {
		return s.keys.Generate(id)
	}
	return s.keys.Import(id, private)
}

// discard undoes a half finished creation.
//
// Both failures are reported rather than swallowed, because a record without a
// key and a key without a record are each worth knowing about.
func (s *Service) discard(ctx context.Context, id int64, relPath string) {
	if err := s.keys.Remove(relPath); err != nil {
		slog.Error("cannot remove the key of a refused server", "server", id, "error", err)
	}
	if err := s.servers.Delete(ctx, id); err != nil {
		slog.Error("cannot remove a server that could not be finished", "server", id, "error", err)
	}
}

// Update writes the editable fields of a server.
func (s *Service) Update(ctx context.Context, actor Actor, record Server) error {
	current, err := s.servers.Get(ctx, record.ID)
	if err != nil {
		return err
	}

	// The key path and the host key are not editable here. Approving a key is
	// its own action, and the key file is named after the record.
	record.SSHKeyPath = current.SSHKeyPath
	record.HostKey = current.HostKey
	record.Transport = current.Transport
	record.ApplyDefaults()

	if err := record.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrValidation, err)
	}
	if err := s.servers.Update(ctx, record); err != nil {
		return err
	}

	// The connection carries the previous address and credentials, so it has
	// to go even when nothing about it changed.
	s.pool.Remove(record.ID)

	s.writeFor(ctx, actor, audit.ActionServerUpdate, &record.ID, record.Name,
		fmt.Sprintf("Updated server #%d: %s", record.ID, record.Name))
	return nil
}

// Delete removes a server and its private key.
func (s *Service) Delete(ctx context.Context, actor Actor, id int64) error {
	record, err := s.servers.Get(ctx, id)
	if err != nil {
		return err
	}

	s.pool.Remove(id)

	if err := s.servers.Delete(ctx, id); err != nil {
		return err
	}
	if err := s.keys.Remove(record.SSHKeyPath); err != nil {
		// The record is gone either way. The stray key is worth reporting but
		// not worth failing the request over.
		s.writeFor(ctx, actor, audit.ActionServerDelete, nil, record.Name, fmt.Sprintf(
			"Deleted server: %s (the key file could not be removed: %v)", record.Name, err))
		return nil
	}

	s.writeFor(ctx, actor, audit.ActionServerDelete, nil, record.Name,
		"Deleted server: "+record.Name)
	return nil
}

// Get reads one server.
func (s *Service) Get(ctx context.Context, id int64) (Server, error) {
	return s.servers.Get(ctx, id)
}

// List returns every server.
func (s *Service) List(ctx context.Context) ([]Server, error) {
	return s.servers.List(ctx)
}

// PublicKey returns the public half of a server key for the operator to
// install on the target.
func (s *Service) PublicKey(ctx context.Context, id int64) (KeyPair, error) {
	record, err := s.servers.Get(ctx, id)
	if err != nil {
		return KeyPair{}, err
	}

	public, fingerprint, err := s.keys.PublicKey(record.SSHKeyPath)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{RelPath: record.SSHKeyPath, PublicKey: public, Fingerprint: fingerprint}, nil
}

// HostKeyOffer is what a server presents before anyone has approved it.
type HostKeyOffer struct {
	Fingerprint string

	// AuthorizedKey is stored only after the operator approves it, so it
	// travels with the offer rather than being written straight away.
	AuthorizedKey string
}

// ScanHostKey reads the host key a server offers.
func (s *Service) ScanHostKey(ctx context.Context, id int64) (HostKeyOffer, error) {
	record, err := s.servers.Get(ctx, id)
	if err != nil {
		return HostKeyOffer{}, err
	}

	timeouts := s.timeouts()
	fingerprint, authorized, err := transport.ScanHostKey(
		record.TransportConfig(s.dataDir, timeouts.Connect, timeouts.Command))
	if err != nil {
		return HostKeyOffer{}, err
	}
	return HostKeyOffer{Fingerprint: fingerprint, AuthorizedKey: authorized}, nil
}

// TrustHostKey stores the key an operator approved.
//
// The fingerprint the operator saw is passed back in, and the key is only
// stored when the server still offers that same key. Without it, a server that
// changed between the display and the click would be trusted unseen.
func (s *Service) TrustHostKey(ctx context.Context, actor Actor, id int64, fingerprint string) error {
	record, err := s.servers.Get(ctx, id)
	if err != nil {
		return err
	}

	offer, err := s.ScanHostKey(ctx, id)
	if err != nil {
		return err
	}
	if offer.Fingerprint != fingerprint {
		return fmt.Errorf(
			"%w: the server now offers %s, not the %s that was shown",
			ErrValidation, offer.Fingerprint, fingerprint)
	}

	if err := s.servers.SetHostKey(ctx, id, offer.AuthorizedKey); err != nil {
		return err
	}
	// The pooled connection still carries the previous policy.
	s.pool.Remove(id)

	s.writeFor(ctx, actor, audit.ActionServerTrust, &id, record.Name, fmt.Sprintf(
		"Trusted host key for %s: %s", record.Name, offer.Fingerprint))
	return nil
}

// TestResult is the outcome of a connection test.
type TestResult struct {
	OK bool

	// Step names the stage that failed, so the operator knows whether to look
	// at the network, the key, the file or the sudoers rules.
	Step    transport.ProbeStep
	Message string

	// HostKey carries the offer when the panel will not talk to the server
	// until an operator has looked at the fingerprint.
	HostKey *HostKeyOffer

	// HostKeyChanged separates a server nobody has approved yet from one that
	// now offers a different key than the approved one. The second is what a
	// man in the middle looks like, so it is not shown as a first contact.
	HostKeyChanged bool
}

// TestConnection walks the whole path the panel depends on.
func (s *Service) TestConnection(ctx context.Context, id int64) (TestResult, error) {
	record, err := s.servers.Get(ctx, id)
	if err != nil {
		return TestResult{}, err
	}

	timeouts := s.timeouts()
	client, err := s.pool.Get(record.TransportConfig(
		s.dataDir, timeouts.Connect, timeouts.Command))
	if err != nil {
		return TestResult{Step: transport.StepConnect, Message: err.Error()}, nil
	}

	probeErr := client.Probe(ctx)
	if probeErr == nil {
		if err := s.servers.SetReachability(ctx, id, s.now().UTC(), ""); err != nil {
			return TestResult{}, err
		}
		return TestResult{OK: true}, nil
	}

	result := TestResult{Message: probeErr.Error()}
	if step, ok := errors.AsType[*transport.ProbeError](probeErr); ok {
		result.Step = step.Step
	}

	// An unapproved host key is not a fault. The operator has to see the
	// fingerprint and approve it, so the offer travels back with the result. A
	// changed key is a fault, but the operator still needs the new fingerprint
	// to tell a reinstalled server from an impostor.
	unknown := errors.Is(probeErr, transport.ErrHostKeyUnknown)
	changed := errors.Is(probeErr, transport.ErrHostKeyMismatch)
	if unknown || changed {
		result.HostKeyChanged = changed
		if offer, scanErr := s.ScanHostKey(ctx, id); scanErr == nil {
			result.HostKey = &offer
		}
	}

	if err := s.servers.SetReachability(ctx, id, s.now().UTC(), probeErr.Error()); err != nil {
		return TestResult{}, err
	}
	return result, nil
}

// write records one action.
//
// A failure is logged by the audit package and does not stop the operation.
// The change is already made, and refusing to report it would leave the
// operator unsure whether it happened.
func (s *Service) write(ctx context.Context, actor Actor, action string,
	serverID *int64, details string) {

	s.writeFor(ctx, actor, action, serverID, "", details)
}

// writeFor records one action against a named server.
//
// The name travels with the entry, because the forwarded event names the
// target and a receiver reads a name more easily than a row identifier.
func (s *Service) writeFor(ctx context.Context, actor Actor, action string,
	serverID *int64, serverName, details string) {

	_ = s.audit.Write(ctx, audit.Entry{
		UID:        actor.UID,
		Username:   actor.Username,
		ServerID:   serverID,
		ServerName: serverName,
		Action:     action,
		Details:    details,
		IPAddress:  actor.IPAddress,
	})
}
