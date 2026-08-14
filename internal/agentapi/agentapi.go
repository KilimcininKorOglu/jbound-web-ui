// Package agentapi holds the protocol the panel and an agent speak.
//
// One definition, used by both sides. The panel imports it to build requests
// and read answers, and the agent imports it to do the reverse, so the two
// cannot drift into disagreeing about a field name.
//
// The shape of this protocol follows from what the agent exists to remove. On
// the SSH path the panel sends command text and the target runs it through a
// login shell, and what keeps that safe is a set of exact sudoers rules. Here
// no command text travels at all: the panel names a step, and the agent runs
// whatever its own configuration says that step is. Nothing in a request
// decides which file is written or which program is run.
package agentapi

// Paths of every endpoint. The three reload rungs are three endpoints rather
// than one with a parameter, so the panel's ladder calls three methods and the
// layer above it stays as it was.
const (
	PathInfo          = "/v1/info"
	PathRecords       = "/v1/records"
	PathEnsureInclude = "/v1/ensure-include"
	PathCheckConf     = "/v1/checkconf"
	PathReload        = "/v1/reload"
	PathReloadBack    = "/v1/reload-fallback"
	PathRestart       = "/v1/restart"
	PathStatus        = "/v1/status"
)

// Version is the protocol this package describes. An agent reports it in Info
// so a panel meeting an older one can say so rather than fail obscurely.
const Version = "1"

// MaxBodyBytes bounds a request and a response.
//
// Both sides apply it. How much memory the panel sets aside must not be a
// decision the far end makes, and the same holds in reverse. The limit allows
// a base64 encoded records file of about six megabytes, far above any resolver
// and far below what would trouble either host.
const MaxBodyBytes = 8 << 20

// AuthScheme is what the Authorization header carries.
const AuthScheme = "Bearer"

// Info is what an agent says about itself.
type Info struct {
	// Version is the protocol version, not the build.
	Version string `json:"version"`

	// RecordsPath is the file this agent manages. The panel asks rather than
	// tells: every host may name the file differently, and an agent that took
	// the path from the panel would be a way to write any file on the server.
	RecordsPath string `json:"records_path"`

	// IncludeOK reports whether the main configuration reads that file. It is
	// here so the panel can show the problem before a change rather than only
	// after one, which is the difference between a warning and a mystery.
	IncludeOK bool `json:"include_ok"`

	// Steps names the operations this agent has a command for. A step with no
	// command answers StatusStepSkipped, the same way an empty command on the
	// SSH path is skipped rather than failed.
	Steps Steps `json:"steps"`
}

// Steps reports which operations an agent is configured for.
type Steps struct {
	CheckConf      bool `json:"checkconf"`
	Reload         bool `json:"reload"`
	ReloadFallback bool `json:"reload_fallback"`
	Restart        bool `json:"restart"`
	Status         bool `json:"status"`
}

// Records is the file and its digest.
//
// Content is base64 so a records file with any byte in it survives a JSON
// round trip unchanged, which is the same reason the SSH path pipes it
// through base64 rather than sending it raw.
type Records struct {
	Content string `json:"content"`
	SHA256  string `json:"sha256"`
}

// WriteRequest replaces the records file.
//
// It names no path. The agent writes the file its own configuration names,
// and a request that carried one would turn the token into permission to write
// anything on the host.
type WriteRequest struct {
	Content string `json:"content"`

	// ExpectSHA256 is the digest the panel last read. The agent refuses the
	// write when the file no longer matches it, because the read and the write
	// span a network and another operator may have written in between. An
	// empty value skips the check, which is a first write to a target the
	// panel has not read yet.
	ExpectSHA256 string `json:"expect_sha256"`
}

// CommandResult is what a step said.
type CommandResult struct {
	Output string `json:"output"`
}

// StatusResult reports whether the resolver is running.
type StatusResult struct {
	Active bool   `json:"active"`
	Detail string `json:"detail"`
}

// Error is the body of every failing answer.
//
// It carries a class rather than only a message, so the panel maps an answer
// onto its own failure classes without reading English.
type Error struct {
	Class   string `json:"class"`
	Message string `json:"message"`
}

// Failure classes an agent reports.
const (
	ClassAuth     = "auth"
	ClassConflict = "conflict"
	ClassCommand  = "command_failed"
	ClassSkipped  = "step_skipped"
	ClassBadInput = "bad_input"
	ClassInternal = "internal"
)

// StatusStepSkipped is the status code for a step the agent has no command
// for. It is not an error: an agent whose configuration does not name a
// restart command keeps working without one, and the panel's ladder moves on
// to the next rung.
const StatusStepSkipped = 501
