package dnsquery

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"unbound-web/internal/dnsfile"
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
	q := New("/usr/bin/dig", time.Second)
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
