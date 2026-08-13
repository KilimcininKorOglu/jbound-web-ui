package server

import (
	"context"
	"fmt"

	"unbound-web/internal/audit"
)

// CreateGroup stores a new group.
func (s *Service) CreateGroup(ctx context.Context, actor Actor, group Group) (Group, error) {
	if err := group.Validate(); err != nil {
		return Group{}, fmt.Errorf("%w: %v", ErrValidation, err)
	}
	if err := s.requireExistingServers(ctx, group.ServerIDs); err != nil {
		return Group{}, err
	}

	stored, err := s.groups.Create(ctx, group)
	if err != nil {
		return Group{}, err
	}

	s.write(ctx, actor, audit.ActionGroupCreate, nil, "Created group: "+stored.Name)
	return stored, nil
}

// UpdateGroup writes a group and replaces its membership.
func (s *Service) UpdateGroup(ctx context.Context, actor Actor, group Group) error {
	if err := group.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrValidation, err)
	}
	if err := s.requireExistingServers(ctx, group.ServerIDs); err != nil {
		return err
	}
	if err := s.groups.Update(ctx, group); err != nil {
		return err
	}

	s.write(ctx, actor, audit.ActionGroupUpdate, nil, fmt.Sprintf(
		"Updated group #%d: %s (%d members)", group.ID, group.Name, len(group.ServerIDs)))
	return nil
}

// DeleteGroup removes a group. The servers themselves stay.
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

// requireExistingServers rejects a membership that names a server which is not
// there.
//
// The foreign key would refuse it as well, but the message would name a
// constraint rather than the server the operator picked.
func (s *Service) requireExistingServers(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	known := map[int64]bool{}
	servers, err := s.servers.List(ctx)
	if err != nil {
		return err
	}
	for _, record := range servers {
		known[record.ID] = true
	}

	for _, id := range ids {
		if !known[id] {
			return fmt.Errorf("%w: server %d does not exist", ErrValidation, id)
		}
	}
	return nil
}
