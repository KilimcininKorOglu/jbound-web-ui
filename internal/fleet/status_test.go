package fleet

import (
	"testing"

	"jbound/internal/i18n"
)

// englishCatalog is the source language of the panel, which is what these
// sentences are written in.
func englishCatalog(t *testing.T) Catalog {
	t.Helper()

	catalogs, err := i18n.Load()
	if err != nil {
		t.Fatalf("cannot load the catalogues: %v", err)
	}
	return catalogs.Catalog(i18n.Default)
}

func statusOf(entries ...ServerStatus) Status {
	return Status{Servers: entries}
}

func TestTheSummaryNamesHowManyServersLagBehind(t *testing.T) {
	status := statusOf(
		ServerStatus{Name: "dns1", Enabled: true, Pending: true},
		ServerStatus{Name: "dns2", Enabled: true, Pending: true},
		ServerStatus{Name: "dns3", Enabled: true},
	)

	if got := status.Summary(englishCatalog(t)); got != "2 of 3 servers have unapplied changes." {
		t.Errorf("summary = %q", got)
	}
	if !status.Pending() {
		t.Error("a target with unapplied changes does not read as pending")
	}
}

func TestADisabledServerIsLeftOutOfTheCount(t *testing.T) {
	// A reload skips it, so counting it would report work that is not there.
	status := statusOf(
		ServerStatus{Name: "dns1", Enabled: true, Pending: true},
		ServerStatus{Name: "dns2", Pending: true},
	)

	pending, total := status.Counts()
	if pending != 1 || total != 1 {
		t.Fatalf("counts = %d of %d", pending, total)
	}
	if got := status.Summary(englishCatalog(t)); got != "This server has unapplied changes." {
		t.Errorf("summary = %q", got)
	}
}

func TestASettledTargetSaysSo(t *testing.T) {
	status := statusOf(
		ServerStatus{Name: "dns1", Enabled: true},
		ServerStatus{Name: "dns2", Enabled: true},
	)

	if status.Pending() {
		t.Error("a settled target reads as pending")
	}
	if got := status.Summary(englishCatalog(t)); got != "Every server has loaded its current file." {
		t.Errorf("summary = %q", got)
	}
}

func TestAnEmptyTargetSaysSo(t *testing.T) {
	if got := statusOf().Summary(englishCatalog(t)); got != "There is no enabled server in this target." {
		t.Errorf("summary = %q", got)
	}
}

func TestTheStatusNamesTheServersItCannotVouchFor(t *testing.T) {
	// A status drawn from a cache nobody refreshed recently may already have
	// moved on, and the bar has to say which servers those are.
	status := statusOf(
		ServerStatus{Name: "dns1", Enabled: true, Stale: true},
		ServerStatus{Name: "dns2", Enabled: true},
		ServerStatus{Name: "dns3", Stale: true},
	)

	stale := status.Stale()
	if len(stale) != 1 || stale[0] != "dns1" {
		t.Errorf("stale = %v", stale)
	}
}
