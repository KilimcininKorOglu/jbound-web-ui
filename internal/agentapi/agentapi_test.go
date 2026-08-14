package agentapi_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"jbound/internal/agentapi"
)

func TestNoRequestCarriesAPath(t *testing.T) {
	// The whole safety argument of the agent rests on this. The panel names a
	// step and the agent decides which file that step touches, so a stolen
	// token cannot become permission to write /etc/unbound/unbound.conf or an
	// authorized_keys file on every managed server.
	//
	// The check is on the request types alone. Info travels the other way: the
	// agent reports its path, which is the direction that stays safe.
	requests := []any{
		agentapi.WriteRequest{},
	}

	for _, request := range requests {
		typ := reflect.TypeOf(request)
		for field := range typ.Fields() {
			name := strings.ToLower(field.Name)
			for _, forbidden := range []string{"path", "file", "dir", "cmd", "command"} {
				if strings.Contains(name, forbidden) {
					t.Errorf("%s carries a %s field: %s", typ.Name(), forbidden, field.Name)
				}
			}
		}
	}
}

func TestEveryEndpointIsUnderTheVersionPrefix(t *testing.T) {
	// A path without it would break the moment the protocol changes, and the
	// agent is the piece an operator upgrades last.
	paths := []string{
		agentapi.PathInfo, agentapi.PathRecords, agentapi.PathEnsureInclude,
		agentapi.PathCheckConf, agentapi.PathReload, agentapi.PathReloadBack,
		agentapi.PathRestart, agentapi.PathStatus,
	}

	seen := map[string]bool{}
	for _, path := range paths {
		if !strings.HasPrefix(path, "/v"+agentapi.Version+"/") {
			t.Errorf("%q is outside the version prefix", path)
		}
		if seen[path] {
			t.Errorf("%q is registered twice", path)
		}
		seen[path] = true
	}
}

func TestTheWireNamesSurviveARoundTrip(t *testing.T) {
	// The two sides are built from this one package, but they ship as separate
	// binaries and an operator may run them a version apart. A field that
	// silently renamed itself would read as an empty file rather than as a
	// mismatch.
	const encoded = `{"version":"1","records_path":"/etc/unbound/local_records.conf",` +
		`"include_ok":true,"steps":{"checkconf":true,"reload":true,` +
		`"reload_fallback":false,"restart":false,"status":true}}`

	var info agentapi.Info
	if err := json.Unmarshal([]byte(encoded), &info); err != nil {
		t.Fatalf("cannot read the answer: %v", err)
	}

	if info.RecordsPath != "/etc/unbound/local_records.conf" {
		t.Errorf("records path = %q", info.RecordsPath)
	}
	if !info.IncludeOK {
		t.Error("the include flag did not survive")
	}
	if !info.Steps.Reload || info.Steps.Restart {
		t.Errorf("steps = %+v", info.Steps)
	}

	again, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("cannot write the answer back: %v", err)
	}
	if string(again) != encoded {
		t.Errorf("the answer came back as:\n%s\nwant:\n%s", again, encoded)
	}
}

func TestTheBodyLimitIsLargeEnoughForARealFileAndNoLarger(t *testing.T) {
	// Base64 costs a third, so the limit has to clear a resolver's file with
	// room to spare while staying somewhere a panel can hold in memory for
	// every server it writes to at once.
	const megabyte = 1 << 20
	if agentapi.MaxBodyBytes < 4*megabyte {
		t.Errorf("the limit is %d bytes, too small for a real records file",
			agentapi.MaxBodyBytes)
	}
	if agentapi.MaxBodyBytes > 32*megabyte {
		t.Errorf("the limit is %d bytes, large enough to be a way to exhaust a host",
			agentapi.MaxBodyBytes)
	}
}
