// Package dnsquery asks a managed resolver what it answers for a name.
//
// The query runs on the panel host and reaches the server over the network,
// rather than running dig through the remote shell. The domain is operator
// input, and a shell would turn it into an injection surface. Running it here
// with exec and no shell closes that surface, and the answer is the one a real
// client would get.
package dnsquery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"unbound-web/internal/dnsfile"
)

// ErrTool marks a dig the panel host does not have or cannot run.
var ErrTool = errors.New("cannot run the dns client")

// Answer is what one server replied.
type Answer struct {
	ServerID   int64
	ServerName string
	Host       string

	// Records holds one line per answer, as dig prints them in short form.
	Records []string

	// Err carries why a server could not be asked. The others still answer.
	Err error
}

// OK reports whether the server answered at all.
func (a Answer) OK() bool { return a.Err == nil }

// Empty reports whether the server answered with nothing, which is the case
// worth seeing after a record was added and the rules were not applied.
func (a Answer) Empty() bool { return a.Err == nil && len(a.Records) == 0 }

// Querier asks one resolver at a time.
type Querier struct {
	dig string

	// timeout is read per query, so a value changed on the settings page
	// applies to the next question rather than to the next restart.
	timeout func() time.Duration

	// run is the command runner, replaced in tests so the package can be
	// covered without a dig on the host running them.
	run func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// New builds the querier.
func New(digPath string, timeout func() time.Duration) *Querier {
	return &Querier{dig: digPath, timeout: timeout, run: runCommand}
}

// Ask queries one server for one name.
//
// The name is validated first. Everything the panel sends to dig is either a
// validated name, a configured path or a fixed flag.
func (q *Querier) Ask(ctx context.Context, host, domain, recordType string) ([]string, error) {
	if err := dnsfile.ValidateFQDN(domain); err != nil {
		return nil, err
	}
	if recordType != "" {
		if err := dnsfile.ValidateRecordType(recordType); err != nil {
			return nil, err
		}
	}

	// One budget, read once, so the flag and the deadline below cannot describe
	// two different limits.
	budget := q.timeout()

	args := []string{"@" + host, domain}
	if recordType != "" {
		args = append(args, recordType)
	}
	// One try. A retry would spend the budget twice over and the operator
	// asked one resolver one question.
	args = append(args, "+short",
		fmt.Sprintf("+timeout=%d", digSeconds(budget)), "+tries=1")

	// The deadline sits past the flag, so a slow resolver is reported by dig,
	// which says what it was waiting for, rather than by a killed process.
	ctx, cancel := context.WithTimeout(ctx, budget+queryGrace)
	defer cancel()

	output, err := q.run(ctx, q.dig, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTool, err)
	}
	return lines(output), nil
}

// queryGrace is how much longer the panel waits than dig does.
//
// Without it the context deadline and dig's own timeout land together, and
// which of the two fires first decides whether the operator reads an answer
// about the resolver or about a signal.
const queryGrace = time.Second

// digSeconds renders a duration as the whole seconds dig accepts.
//
// dig takes no fraction, and a budget under a second would round to zero,
// which it reads as no wait at all.
func digSeconds(budget time.Duration) int {
	return max(1, int(budget/time.Second))
}

// lines splits dig's short output into one entry per answer.
func lines(output []byte) []string {
	var answers []string
	for line := range strings.SplitSeq(string(output), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			answers = append(answers, trimmed)
		}
	}
	return answers
}

// runCommand executes dig without a shell.
//
// The two streams stay apart. dig writes its answers to stdout and its
// complaints to stderr, and mixing them would turn a warning into an answer.
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer

	command := exec.CommandContext(ctx, name, args...)
	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		if detail == "" {
			return nil, err
		}
		return nil, fmt.Errorf("%v: %s", err, detail)
	}
	return stdout.Bytes(), nil
}
