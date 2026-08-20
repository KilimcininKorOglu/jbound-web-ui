package fleet

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
//
// The catalogue is a parameter rather than a package level default, because
// the sentence is read by a person and the panel speaks more than one
// language.
func (s Status) Summary(catalog Catalog) string {
	pending, total := s.Counts()

	switch {
	case total == 0:
		return catalog.T("status.no_enabled_server")
	case pending == 0:
		return catalog.T("status.all_loaded")
	case total == 1:
		return catalog.T("status.one_pending")
	default:
		return catalog.Tf("status.some_pending", pending, total)
	}
}

// Catalog is the part of the message catalogue this package needs.
//
// An interface rather than the catalogue type, so the fleet does not depend on
// the package that holds the interface texts.
type Catalog interface {
	T(key string) string
	Tf(key string, args ...any) string
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
