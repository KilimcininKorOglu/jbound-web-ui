package server

import (
	"context"
	"fmt"

	"jbound/internal/audit"
)

// CreateGroup stores a new group.
//
// A new group has no member yet, so it can carry no source. The form offers
// none either, and the check below is what keeps a hand written request from
// naming one.
func (s *Service) CreateGroup(ctx context.Context, actor Actor, group Group) (Group, error) {
	if err := group.Validate(); err != nil {
		return Group{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	if err := s.requireSourceIsMember(ctx, group); err != nil {
		return Group{}, err
	}

	stored, err := s.groups.Create(ctx, group)
	if err != nil {
		return Group{}, err
	}

	s.write(ctx, actor, audit.ActionGroupCreate, nil, "Created group: "+stored.Name)
	return stored, nil
}

// UpdateGroup writes the group.
//
// Which servers are in it is not decided here. A server names its own group, so
// this only carries the name, the description and the reference a mirror copies
// from.
func (s *Service) UpdateGroup(ctx context.Context, actor Actor, group Group) error {
	if err := group.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrValidation, err)
	}
	if err := s.requireSourceIsMember(ctx, group); err != nil {
		return err
	}
	if err := s.groups.Update(ctx, group); err != nil {
		return err
	}

	s.write(ctx, actor, audit.ActionGroupUpdate, nil, fmt.Sprintf(
		"Updated group #%d: %s (source %s)",
		group.ID, group.Name, idLabel(group.SourceServerID)))
	return nil
}

// DeleteGroup removes a group. The servers themselves stay, and the foreign key
// leaves them ungrouped.
func (s *Service) DeleteGroup(ctx context.Context, actor Actor, id int64) error {
	group, err := s.groups.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := s.groups.Delete(ctx, id); err != nil {
		return err
	}

	s.write(ctx, actor, audit.ActionGroupDelete, nil, "Deleted group: "+group.Name)
	return nil
}

// GetGroup reads one group.
func (s *Service) GetGroup(ctx context.Context, id int64) (Group, error) {
	return s.groups.Get(ctx, id)
}

// ListGroups returns every group.
func (s *Service) ListGroups(ctx context.Context) ([]Group, error) {
	return s.groups.List(ctx)
}

// Members returns the servers of a group, including none at all.
//
// A group somebody has just created is empty, and its page has to open rather
// than fail. What may not happen against an empty group is a write, which is
// what Targets is for.
func (s *Service) Members(ctx context.Context, groupID int64) ([]Server, error) {
	if _, err := s.groups.Get(ctx, groupID); err != nil {
		return nil, err
	}
	return s.groups.Members(ctx, groupID)
}

// Targets returns the servers an operation against a group will reach.
//
// A group with no member is refused rather than reported as a success with
// nothing done, because the operator would have no way to tell the difference.
func (s *Service) Targets(ctx context.Context, groupID int64) ([]Server, error) {
	group, err := s.groups.Get(ctx, groupID)
	if err != nil {
		return nil, err
	}

	members, err := s.groups.Members(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if len(members) == 0 {
		return nil, fmt.Errorf("%w: group %s has no members", ErrValidation, group.Name)
	}
	return members, nil
}

// SourceServer returns the server a mirror onto this group copies from.
//
// A source that has left the group, been disabled or lost its host key reads as
// none, so the answer is what may actually be copied rather than what the row
// last said.
func (s *Service) SourceServer(ctx context.Context, groupID int64) (Server, bool, error) {
	if groupID <= 0 {
		return Server{}, false, nil
	}

	group, err := s.groups.Get(ctx, groupID)
	if err != nil {
		return Server{}, false, err
	}
	if group.SourceServerID <= 0 {
		return Server{}, false, nil
	}

	record, err := s.servers.Get(ctx, group.SourceServerID)
	if err != nil {
		return Server{}, false, nil
	}
	if record.GroupID != groupID || !record.Enabled || !record.Trusted() {
		return Server{}, false, nil
	}
	return record, true, nil
}

// requireSourceIsMember refuses a reference that is not in the group.
//
// The database would allow it: the column only says the row is a server. What
// makes it wrong is that a mirror copies the source onto every member, so a
// source from elsewhere would replace the group's records with another group's.
func (s *Service) requireSourceIsMember(ctx context.Context, group Group) error {
	if group.SourceServerID == 0 {
		return nil
	}

	record, err := s.servers.Get(ctx, group.SourceServerID)
	if err != nil {
		return fmt.Errorf("%w: server %d does not exist", ErrValidation, group.SourceServerID)
	}
	if record.GroupID != group.ID {
		return fmt.Errorf("%w: %s is not a member of this group", ErrValidation, record.Name)
	}
	if !record.Enabled {
		return fmt.Errorf("%w: %s is disabled", ErrValidation, record.Name)
	}
	return nil
}

// releaseSourceOf clears every group that names this server as its source but
// no longer holds it.
//
// It runs after a server moved group or was disabled. A reference that points
// at a server the group cannot copy from would leave the operator a button that
// fails at the far end.
func (s *Service) releaseSourceOf(ctx context.Context, record Server) error {
	groups, err := s.groups.List(ctx)
	if err != nil {
		return err
	}

	for _, group := range groups {
		if group.SourceServerID != record.ID {
			continue
		}
		if group.ID == record.GroupID && record.Enabled {
			continue
		}

		group.SourceServerID = 0
		if err := s.groups.Update(ctx, group); err != nil {
			return err
		}
	}
	return nil
}

// idLabel writes an optional identifier for an audit line.
func idLabel(id int64) string {
	if id <= 0 {
		return "none"
	}
	return fmt.Sprintf("#%d", id)
}
