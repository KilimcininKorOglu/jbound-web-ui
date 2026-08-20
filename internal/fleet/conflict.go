package fleet

import (
	"context"
	"slices"
	"strings"

	"jbound/internal/dnsfile"
)

// What a submitted record runs into on the target.
const (
	// ConflictExists means the target already holds this exact record.
	ConflictExists = "exists"

	// ConflictNameTaken means the name and type are there with another value.
	// A file may hold both, and the resolver would answer with either, so this
	// is a question for the operator rather than a refusal.
	ConflictNameTaken = "name_taken"
)

// Conflict is what one submitted record runs into.
type Conflict struct {
	// Row is the one based position in the submission, so a batch can point at
	// the line the operator typed.
	Row int

	Kind   string
	Wanted dnsfile.Record

	// Existing is the record in the way. It stays empty for ConflictExists,
	// where the record in the way is the one being written.
	Existing dnsfile.Record

	// Servers names the servers this was read from, in the order the target
	// lists them.
	Servers []string

	// Everywhere reports whether every enabled server of the target is in
	// Servers. A record that is already on some of them is still missing from
	// the others, and writing it there is the ordinary thing to do.
	Everywhere bool
}

// Conflicts reports what a set of records would run into on the target.
//
// It reads the cache rather than the servers, because it answers a form
// submission and a round of connections would make every add wait on the
// slowest machine. The files stay authoritative: the write path reads them and
// refuses the record there, so a cache that was stale costs one refused row in
// the report rather than a second value on a server.
func (s *Service) Conflicts(ctx context.Context, target Target,
	records []dnsfile.Record) ([]Conflict, error) {

	members, _, err := s.writer.Members(ctx, target)
	if err != nil {
		return nil, err
	}

	byServer, err := s.records.ByServer(ctx, Query{
		Scope: target.Scope, ServerID: target.ServerID, GroupID: target.GroupID})
	if err != nil {
		return nil, err
	}

	// A disabled server joins no operation, so what it holds decides nothing.
	enabled := make([]conflictServer, 0, len(members))
	for _, record := range members {
		if record.Enabled {
			enabled = append(enabled, conflictServer{id: record.ID, name: record.Name})
		}
	}

	var conflicts []Conflict
	for i, wanted := range records {
		conflict := Conflict{Row: i + 1, Wanted: wanted}

		for _, member := range enabled {
			held, kind := runsInto(byServer[member.id], wanted)
			if kind == "" {
				continue
			}
			// A name taken on one server outranks the record being there on
			// another: the choice it asks for covers both.
			if conflict.Kind == "" || (conflict.Kind == ConflictExists && kind == ConflictNameTaken) {
				conflict.Kind, conflict.Existing, conflict.Servers = kind, held, nil
			}
			if conflict.Kind == kind {
				conflict.Servers = append(conflict.Servers, member.name)
			}
		}

		if conflict.Kind == "" {
			continue
		}
		conflict.Everywhere = len(conflict.Servers) == len(enabled)
		conflicts = append(conflicts, conflict)
	}
	return conflicts, nil
}

// conflictServer is one member of the target, reduced to what a conflict
// needs. The package name server is taken by the package it imports.
type conflictServer struct {
	id   int64
	name string
}

// runsInto reports what one server's records do to a submitted one.
func runsInto(held []dnsfile.Record, wanted dnsfile.Record) (dnsfile.Record, string) {
	var taken dnsfile.Record
	var found bool

	for _, record := range held {
		if keyOf(record) == keyOf(wanted) {
			return dnsfile.Record{}, ConflictExists
		}
		if !found && dnsfile.OneValuePerName(wanted.Type) &&
			record.Type == wanted.Type && sameFQDN(record.FQDN, wanted.FQDN) {
			taken, found = record, true
		}
	}
	if found {
		return taken, ConflictNameTaken
	}
	return dnsfile.Record{}, ""
}

// sameFQDN compares two names the way the file does, where the trailing dot is
// optional.
func sameFQDN(a, b string) bool {
	return strings.TrimSuffix(a, ".") == strings.TrimSuffix(b, ".")
}

// NameTaken reports whether any of the conflicts is a choice for the operator.
func NameTaken(conflicts []Conflict) bool {
	return slices.ContainsFunc(conflicts, func(c Conflict) bool {
		return c.Kind == ConflictNameTaken
	})
}

// AlreadyEverywhere reports whether every submitted record is already on every
// server of the target, which is the one case where there is nothing to write.
func AlreadyEverywhere(conflicts []Conflict, records int) bool {
	if len(conflicts) != records || records == 0 {
		return false
	}
	return !slices.ContainsFunc(conflicts, func(c Conflict) bool {
		return c.Kind != ConflictExists || !c.Everywhere
	})
}
