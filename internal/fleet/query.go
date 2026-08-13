package fleet

import (
	"context"
	"strings"
	"sync"

	"unbound-web/internal/audit"
	"unbound-web/internal/dnsfile"
	"unbound-web/internal/server"
)

// NameQuerier asks one resolver what it answers for a name.
//
// The fleet layer only fans the question out. How the question travels is the
// business of the package behind this interface.
type NameQuerier interface {
	Ask(ctx context.Context, host, domain, recordType string) ([]string, error)
}

// QueryResult is what one server answered.
type QueryResult struct {
	ServerID   int64
	ServerName string
	Host       string

	Records []string
	Skipped bool
	Err     error
}

// Answer folds the records into one comparable string.
func (q QueryResult) Answer() string { return strings.Join(q.Records, " ") }

// QueryReport is what a whole target answered.
type QueryReport struct {
	Domain    string
	Type      string
	GroupName string
	Results   []QueryResult
}

// Agree reports whether every server that answered gave the same answer.
//
// This is the reason a query runs against a group at all: a record that
// resolves on two servers and not on the third is drift the record table
// cannot show, because the file may well be identical and the resolver behind.
func (r QueryReport) Agree() bool {
	var first string
	seen := false

	for _, result := range r.Results {
		if result.Skipped || result.Err != nil {
			continue
		}
		answer := result.Answer()
		if !seen {
			first, seen = answer, true
			continue
		}
		if answer != first {
			return false
		}
	}
	return true
}

// Failed reports how many servers could not be asked.
func (r QueryReport) Failed() int {
	failed := 0
	for _, result := range r.Results {
		if result.Err != nil {
			failed++
		}
	}
	return failed
}

// Query asks every server of a target what it answers for one name.
func (s *Service) Query(ctx context.Context, actor server.Actor, target Target,
	domain, recordType string) (QueryReport, error) {

	// The name is operator input and it becomes a command argument. The
	// querier checks it as well, and it is checked here so the rule holds
	// whichever querier is behind the interface.
	if err := dnsfile.ValidateFQDN(domain); err != nil {
		return QueryReport{}, err
	}
	if recordType != "" {
		if err := dnsfile.ValidateRecordType(recordType); err != nil {
			return QueryReport{}, err
		}
	}

	members, groupName, err := s.writer.Members(ctx, target)
	if err != nil {
		return QueryReport{}, err
	}

	report := QueryReport{
		Domain:    domain,
		Type:      recordType,
		GroupName: groupName,
		Results:   make([]QueryResult, len(members)),
	}

	var wait sync.WaitGroup
	for i, record := range members {
		wait.Add(1)
		go func() {
			defer wait.Done()
			report.Results[i] = s.ask(ctx, record, domain, recordType)
		}()
	}
	wait.Wait()

	// A query changes nothing, so one row names what was asked and where. The
	// server column carries the machine only when a single one was asked.
	s.auditQuery(ctx, actor, target, members, report)
	return report, nil
}

// ask queries one server.
//
// The query leaves the panel host over the network, so a disabled server is
// still reachable. It is skipped anyway: the operator took it out of the
// fleet, and an answer from it would read as part of the fleet's state.
func (s *Service) ask(ctx context.Context, record server.Server,
	domain, recordType string) QueryResult {

	result := QueryResult{
		ServerID:   record.ID,
		ServerName: record.Name,
		Host:       record.Host,
	}
	if !record.Enabled {
		result.Skipped = true
		return result
	}

	records, err := s.queries.Ask(ctx, record.Host, domain, recordType)
	if err != nil {
		result.Err = err
		return result
	}
	result.Records = records
	return result
}

// auditQuery records what was asked, once per query rather than once per
// server. A query reads, and a row for every member of a large group would
// bury the changes the log exists for.
func (s *Service) auditQuery(ctx context.Context, actor server.Actor, target Target,
	members []server.Server, report QueryReport) {

	details := "Queried: " + report.Domain
	if report.Type != "" {
		details += " " + report.Type
	}

	var serverID *int64
	switch {
	case report.GroupName != "":
		details += " (group " + report.GroupName + ")"
	case target.Scope == ScopeServer && len(members) == 1:
		details += " on " + members[0].Name
		id := members[0].ID
		serverID = &id
	default:
		details += " on every server"
	}

	_ = s.audit.Write(ctx, audit.Entry{
		UID:       actor.UID,
		Username:  actor.Username,
		ServerID:  serverID,
		Action:    audit.ActionDNSQuery,
		Details:   details,
		IPAddress: actor.IPAddress,
	})
}
