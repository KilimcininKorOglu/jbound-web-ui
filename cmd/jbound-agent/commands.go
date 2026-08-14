package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// Step failures. Each one becomes a different answer, because the panel maps
// them onto its own classes and the operator action differs for each.
var (
	// errSkipped is a step this host has no command for. It is not a failure:
	// a resolver without a control socket has no reload command, and the
	// panel's ladder moves on to the next rung.
	errSkipped = errors.New("no command is configured for this step")

	// errConflict is a write whose expected digest no longer matches. Another
	// operator wrote between the panel's read and its write.
	errConflict = errors.New("the file changed since it was read")
)

// commandError is a step that ran and refused.
//
// The output travels with it. A configuration the resolver will not load says
// why on stderr, and "the change failed" would send the operator to this host
// to read what the panel could have shown them.
type commandError struct {
	Output string
	Err    error
}

func (e *commandError) Error() string {
	detail := strings.TrimSpace(e.Output)
	if detail == "" {
		detail = "no output"
	}
	return detail
}

func (e *commandError) Unwrap() error { return e.Err }

// maxOutputBytes bounds what one step may say.
//
// A resolver that dislikes a configuration can produce pages of it, and the
// answer travels to a panel that holds one of these per server in a fleet
// operation.
const maxOutputBytes = 64 << 10

// run executes one configured step and returns everything it said.
//
// There is no shell. The command was split into an argv list at load, and
// nothing from the request reaches it, so this cannot become a way to run
// something the configuration does not name.
func (a *Agent) run(ctx context.Context, command Command) (string, error) {
	if !command.Configured() {
		return "", errSkipped
	}

	ctx, cancel := context.WithTimeout(ctx, a.cfg.CommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, command[0], command[1:]...)

	// The environment is emptied rather than inherited. A step runs as root,
	// and a variable that reached this process from somewhere else has no
	// business steering what a resolver does.
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}

	output, err := cmd.CombinedOutput()
	if len(output) > maxOutputBytes {
		output = output[:maxOutputBytes]
	}
	text := strings.TrimSpace(string(output))

	if err != nil {
		if ctx.Err() != nil {
			return text, fmt.Errorf("%s did not finish within %s",
				command[0], a.cfg.CommandTimeout)
		}
		return text, &commandError{Output: text, Err: err}
	}
	return text, nil
}

// serviceStatus reports whether the resolver is running.
//
// A non zero exit is the answer rather than a failure. systemctl is-active
// exits 3 for a stopped unit, and that is information the panel needs after a
// reload rather than a broken connection.
func (a *Agent) serviceStatus(ctx context.Context) (bool, string, error) {
	output, err := a.run(ctx, a.cfg.StatusCmd)
	if err == nil {
		return true, output, nil
	}

	var refused *commandError
	if errors.As(err, &refused) {
		return false, output, nil
	}
	return false, output, err
}
