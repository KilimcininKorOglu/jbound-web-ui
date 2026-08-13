package server

import (
	"fmt"
	"strings"
	"time"
)

// Group targets several servers with one operation.
//
// A server may belong to more than one group, so a pair of resolvers can be
// changed together while each still appears in a narrower group of its own.
type Group struct {
	ID          int64
	Name        string
	Description string
	ServerIDs   []int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Validate checks a group before it is stored.
func (g Group) Validate() error {
	var problems []string

	if !namePattern.MatchString(g.Name) {
		problems = append(problems,
			"name must start with a letter or digit and may hold letters, digits, dot, dash and underscore")
	}
	if len(g.Description) > 255 {
		problems = append(problems, "description is longer than 255 characters")
	}

	seen := map[int64]bool{}
	for _, id := range g.ServerIDs {
		if id <= 0 {
			problems = append(problems, fmt.Sprintf("server id %d is not valid", id))
			continue
		}
		if seen[id] {
			problems = append(problems, fmt.Sprintf("server %d is listed twice", id))
		}
		seen[id] = true
	}

	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

// IsEmpty reports whether the group targets no server.
//
// An operation against an empty group is refused rather than reported as a
// success, because nothing would reach a resolver.
func (g Group) IsEmpty() bool { return len(g.ServerIDs) == 0 }
