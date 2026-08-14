package dnsquery

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"jbound/internal/dnsfile"
	"jbound/internal/settings"
)

// recorder captures what the querier would have run.
type recorder struct {
	name   string
	args   []string
	output string
	err    error
}

func (r *recorder) run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.name, r.args = name, args
	return []byte(r.output), r.err
}

func newQuerier(rec *recorder) *Querier {
	q := New("/usr/bin/dig", settings.Fixed(time.Second))
	q.run = rec.run
	return q
}

func TestTheQueryNamesTheServerAndTheName(t *testing.T) {
	rec := &recorder{output: "192.0.2.10\n"}

	answers, err := newQuerier(rec).Ask(context.Background(), "dns1", "www.example.net", "A")
	if err != nil {
		t.Fatalf("Ask returned an error: %v", err)
	}
	if len(answers) != 1 || answers[0] != "192.0.2.10" {
		t.Fatalf("answers = %v", answers)
	}

	if rec.name != "/usr/bin/dig" {
		t.Errorf("the configured client was not used: %q", rec.name)
	}
	for _, want := range []string{"@dns1", "www.example.net", "A", "+short"} {
		if !slices.Contains(rec.args, want) {
			t.Errorf("the arguments do not carry %q: %v", want, rec.args)
		}
	}
}

func TestTheConfiguredTimeoutReachesTheClient(t *testing.T) {
	// dig has a retry budget of its own. Wired to nothing, it gave up after a
	// fixed two seconds and every longer value the operator saved was inert.
	cases := []struct {
		budget time.Duration
		want   string
	}{
		{budget: 30 * time.Second, want: "+timeout=30"},
		{budget: 2 * time.Minute, want: "+timeout=120"},
		// dig takes whole seconds, and zero would read as no wait at all.
		{budget: 900 * time.Millisecond, want: "+timeout=1"},
	}

	for _, testCase := range cases {
		rec := &recorder{}
		querier := New("/usr/bin/dig", settings.Fixed(testCase.budget))
		querier.run = rec.run

		if _, err := querier.Ask(context.Background(), "dns1", "www.example.net", "A"); err != nil {
			t.Fatalf("Ask returned an error: %v", err)
		}
		if !slices.Contains(rec.args, testCase.want) {
			t.Errorf("a budget of %s produced %v, want %s",
				testCase.budget, rec.args, testCase.want)
		}
	}
}

func TestThePanelWaitsLongerThanTheClientDoes(t *testing.T) {
	// A resolver that never answers has to be reported by dig, which says what
	// it was waiting for, rather than by a process the deadline killed.
	rec := &recorder{}
	querier := New("/usr/bin/dig", settings.Fixed(5*time.Second))

	var deadline time.Time
	querier.run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		deadline, _ = ctx.Deadline()
		return rec.run(ctx, name, args...)
	}

	if _, err := querier.Ask(context.Background(), "dns1", "www.example.net", "A"); err != nil {
		t.Fatalf("Ask returned an error: %v", err)
	}
	if deadline.IsZero() {
		t.Fatal("the query ran with no deadline")
	}
	if left := time.Until(deadline); left <= 5*time.Second {
		t.Errorf("the deadline is %s away, which is not past the %s dig waits",
			left, 5*time.Second)
	}
}

func TestAQueryWithoutATypeAsksForWhateverIsThere(t *testing.T) {
	rec := &recorder{}

	if _, err := newQuerier(rec).Ask(context.Background(), "dns1", "www.example.net", ""); err != nil {
		t.Fatalf("Ask returned an error: %v", err)
	}
	for _, unwanted := range dnsfile.Types {
		if slices.Contains(rec.args, unwanted) {
			t.Errorf("an empty type became %q: %v", unwanted, rec.args)
		}
	}
}

func TestABadNameNeverReachesTheClient(t *testing.T) {
	// The name is operator input. It becomes an argument rather than a shell
	// word, and it is refused before that as well.
	rec := &recorder{}

	for _, name := range []string{"example.net; rm -rf /", "www example.net", "", "$(id)"} {
		_, err := newQuerier(rec).Ask(context.Background(), "dns1", name, "")
		if !errors.Is(err, dnsfile.ErrInvalid) {
			t.Errorf("Ask(%q) returned %v, want ErrInvalid", name, err)
		}
	}
	if rec.name != "" {
		t.Errorf("a refused name still ran %s %v", rec.name, rec.args)
	}
}

func TestAnUnmanagedTypeIsRefused(t *testing.T) {
	rec := &recorder{}

	_, err := newQuerier(rec).Ask(context.Background(), "dns1", "www.example.net", "ANY")
	if !errors.Is(err, dnsfile.ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
}

func TestSeveralAnswersComeBackAsSeveralLines(t *testing.T) {
	rec := &recorder{output: "192.0.2.10\n192.0.2.11\n\n"}

	answers, err := newQuerier(rec).Ask(context.Background(), "dns1", "www.example.net", "A")
	if err != nil {
		t.Fatalf("Ask returned an error: %v", err)
	}
	if len(answers) != 2 {
		t.Fatalf("answers = %v, want two without the blank line", answers)
	}
}

func TestAnEmptyAnswerIsNotAFailure(t *testing.T) {
	// A resolver that holds nothing for a name answers with nothing, which is
	// exactly what an operator checks after adding a record.
	rec := &recorder{output: "\n"}

	answers, err := newQuerier(rec).Ask(context.Background(), "dns1", "www.example.net", "")
	if err != nil {
		t.Fatalf("Ask returned an error: %v", err)
	}
	if len(answers) != 0 {
		t.Fatalf("answers = %v, want none", answers)
	}
}

func TestAFailingClientIsReportedAsOne(t *testing.T) {
	rec := &recorder{err: errors.New("exit status 9: no servers could be reached")}

	_, err := newQuerier(rec).Ask(context.Background(), "dns1", "www.example.net", "")
	if !errors.Is(err, ErrTool) {
		t.Fatalf("got %v, want ErrTool", err)
	}
	if !strings.Contains(err.Error(), "no servers could be reached") {
		t.Errorf("the reason was lost: %v", err)
	}
}

func TestAnAnswerReportsWhatCameBack(t *testing.T) {
	cases := []struct {
		name   string
		answer Answer
		ok     bool
		empty  bool
	}{
		{
			name:   "a resolver that replied",
			answer: Answer{Records: []string{"10.0.0.1"}},
			ok:     true,
		},
		{
			// The case worth seeing after a record was added and the rules
			// were never applied.
			name:   "a resolver that knows the name but holds no record",
			answer: Answer{},
			ok:     true,
			empty:  true,
		},
		{
			name:   "a resolver that could not be asked",
			answer: Answer{Err: errors.New("connection refused")},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := testCase.answer.OK(); got != testCase.ok {
				t.Errorf("OK = %v, want %v", got, testCase.ok)
			}
			if got := testCase.answer.Empty(); got != testCase.empty {
				t.Errorf("Empty = %v, want %v", got, testCase.empty)
			}
		})
	}
}

func TestTheRunnerKeepsTheTwoStreamsApart(t *testing.T) {
	// dig writes its answers to stdout and its complaints to stderr. Mixing
	// them would turn a warning into an answer.
	output, err := runCommand(context.Background(),
		"/bin/sh", "-c", "echo 10.0.0.1; echo warning >&2")
	if err != nil {
		t.Fatalf("the command failed: %v", err)
	}
	if strings.TrimSpace(string(output)) != "10.0.0.1" {
		t.Errorf("output = %q, want the answer alone", output)
	}
}

func TestAFailedCommandCarriesItsComplaint(t *testing.T) {
	_, err := runCommand(context.Background(),
		"/bin/sh", "-c", "echo no servers could be reached >&2; exit 9")
	if err == nil {
		t.Fatal("the runner reported success")
	}
	if !strings.Contains(err.Error(), "no servers could be reached") {
		t.Errorf("the reason was dropped: %v", err)
	}
}

func TestAFailureThatOnlyWroteToStdoutIsStillReadable(t *testing.T) {
	_, err := runCommand(context.Background(), "/bin/sh", "-c", "echo bad flag; exit 1")
	if err == nil {
		t.Fatal("the runner reported success")
	}
	if !strings.Contains(err.Error(), "bad flag") {
		t.Errorf("the reason was dropped: %v", err)
	}
}

func TestASilentFailureReportsTheExitStatus(t *testing.T) {
	_, err := runCommand(context.Background(), "/bin/sh", "-c", "exit 2")
	if err == nil {
		t.Fatal("the runner reported success")
	}
	if !strings.Contains(err.Error(), "exit status 2") {
		t.Errorf("the exit status was dropped: %v", err)
	}
}
