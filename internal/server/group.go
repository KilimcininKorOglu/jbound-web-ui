package server

import (
	"fmt"
	"strings"
	"time"
)

// Group owns the servers a record action targets.
//
// A server belongs to one group at most, which is what lets a record belong to
// the group as well: the file a member holds is the group's records and nothing
// else. Which group a server is in is chosen on the server, not here.
type Group struct {
	ID          int64
	Name        string
	Description string

	// SourceServerID names the member a synchronisation copies from. Zero means
	// no reference is chosen, and then nothing may be mirrored onto the group.
	SourceServerID int64

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Validate checks a group before it is stored.
//
// Whether the source is a member of this group is not decided here, because
// membership lives on the server rows. The service checks it against the
// database.
func (g Group) Validate() error {
	var problems []string

	if !namePattern.MatchString(g.Name) {
		problems = append(problems,
			"name must start with a letter or digit and may hold letters, digits, dot, dash and underscore")
	}
	if len(g.Description) > 255 {
		problems = append(problems, "description is longer than 255 characters")
	}
	if g.SourceServerID < 0 {
		problems = append(problems,
			fmt.Sprintf("source server id %d is not valid", g.SourceServerID))
	}

	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}
