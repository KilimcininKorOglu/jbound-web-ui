// Package schedule holds the record of a DNS change left for a later time.
//
// A Job is a fleet operation an operator has not asked the panel to run yet.
// The operation itself is opaque here: it is carried as the JSON the web layer
// already builds for an immediate write, so this package knows nothing about
// records, targets or the fleet. That is what lets the store keep it and the
// fleet run it without either one importing the other.
package schedule

import "time"

// Status is where a job is in its one and only run.
const (
	StatusPending = "pending"
	StatusDone    = "done"
	StatusFailed  = "failed"
)

// OnConflict is what a scheduled addition does when the name already answers.
//
// The choice is made when the job is created, because the timer that runs it
// has no operator to ask. Fail leaves the existing value in place and reports
// the clash; Overwrite writes this value over whatever the name held.
const (
	OnConflictFail      = "fail"
	OnConflictOverwrite = "overwrite"
)

// Kind names the change an operator scheduled, for the listing to show. It is
// the operator's word for the job (add, edit, delete); the operation carries
// the exact fleet kind, which may be add_many for a batch.
const (
	KindAdd    = "add"
	KindEdit   = "edit"
	KindDelete = "delete"
)

// Job is one DNS change waiting for its time.
type Job struct {
	ID int64

	// Kind is the operator's word for the change, shown in the listing.
	Kind string

	// Operation is the fleet.Operation as JSON. This package does not read it;
	// the fleet layer unmarshals it when the job runs.
	Operation []byte

	// Scope with ServerID or GroupID names the target the same way a live
	// request does. The unused identifier is zero.
	Scope    string
	ServerID int64
	GroupID  int64

	// OnConflict is only meaningful for an addition.
	OnConflict string

	// RunAt is when the timer should apply the job, in UTC.
	RunAt time.Time

	Status string

	// RequestedUID and RequestedUsername are the account that scheduled the
	// job. The run is audited against them, because the operator who left the
	// job is who the change belongs to.
	RequestedUID      int
	RequestedUsername string

	// Result is a one line summary of the run, empty until the job has run.
	Result string

	CreatedAt time.Time

	// RanAt is when the job ran, zero until then.
	RanAt time.Time
}
