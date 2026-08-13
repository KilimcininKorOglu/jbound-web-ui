package fleet

import "fmt"

// ServerStatus is where one server stands right now.
type ServerStatus struct {
	ServerID int64
	Name     string

	Enabled bool

	// Pending marks a server whose file carries changes the resolver has not
	// loaded yet, which is what the Apply Rules button exists for.
	Pending bool

	// Stale marks a server the panel has not read recently, so a status drawn
	// from its cache says how old it is rather than presenting it as current.
	Stale bool

	Reachable     bool
	UnboundActive bool
	LastError     string
}

// Status is what a target looks like as a whole.
type Status struct {
	Servers   []ServerStatus
	GroupName string

	// CanApply is false while the listing covers the whole fleet, because a
	// reload needs a single server or a group somebody built on purpose.
	CanApply bool
}

// Counts returns how many servers a reload would cover and how many of them
// carry changes the resolver has not loaded.
//
// A disabled server counts as neither. It is left out of the operation, so
// counting it would make the summary read as work that is not there.
func (s Status) Counts() (pending, total int) {
	for _, entry := range s.Servers {
		if !entry.Enabled {
			continue
		}
		total++
		if entry.Pending {
			pending++
		}
	}
	return pending, total
}

// Pending reports whether any server carries an unapplied change.
func (s Status) Pending() bool {
	pending, _ := s.Counts()
	return pending > 0
}

// Summary is the sentence the status bar shows.
func (s Status) Summary() string {
	pending, total := s.Counts()

	switch {
	case total == 0:
		return "There is no enabled server in this target."
	case pending == 0:
		return "Every server has loaded its current file."
	case total == 1:
		return "This server has unapplied changes."
	default:
		return fmt.Sprintf("%d of %d servers have unapplied changes.", pending, total)
	}
}

// Stale names the servers whose cache is old, so the status bar can say that
// what it reports may already have moved on.
func (s Status) Stale() []string {
	var names []string
	for _, entry := range s.Servers {
		if entry.Enabled && entry.Stale {
			names = append(names, entry.Name)
		}
	}
	return names
}
