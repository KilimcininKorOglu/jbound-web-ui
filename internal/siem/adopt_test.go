package siem

import "testing"

func TestARuleBecomesAReceiver(t *testing.T) {
	for _, tc := range []struct {
		rule string
		want Receiver
	}{
		{"local6.*    @@siem.example.net:514",
			Receiver{ProtocolTCP, "siem.example.net", 514}},
		{"local6.*  @@10.0.0.5:1514",
			Receiver{ProtocolTCP, "10.0.0.5", 1514}},
		// One at sign meant UDP, which is the only place that was written down.
		{"local6.* @collector.example.net:6514",
			Receiver{ProtocolUDP, "collector.example.net", 6514}},
		// A rule that named no port meant the syslog default.
		{"local6.info @@siem.example.net",
			Receiver{ProtocolTCP, "siem.example.net", 514}},
	} {
		got, active, ok := AdoptRule(tc.rule)
		if !ok {
			t.Errorf("AdoptRule(%q) found nothing", tc.rule)
			continue
		}
		if got != tc.want {
			t.Errorf("AdoptRule(%q) = %+v, want %+v", tc.rule, got, tc.want)
		}
		if active != 1 {
			t.Errorf("AdoptRule(%q) counted %d active rules, want 1", tc.rule, active)
		}
	}
}

func TestAFileWithNothingToAdoptSaysSo(t *testing.T) {
	// A panel that never forwarded, and one whose rules are all parked. Neither
	// has a collector to carry over.
	for _, rules := range []string{
		"",
		"\n\n",
		"# local6.*    @@parked.example.net:514",
	} {
		if _, active, ok := AdoptRule(rules); ok || active != 0 {
			t.Errorf("AdoptRule(%q) found a receiver", rules)
		}
	}
}

func TestTheFirstActiveRuleWinsAndTheRestAreCounted(t *testing.T) {
	// A file with several is a file the operator has to look at. Guessing which
	// one they meant would be worse than taking the first and saying how many
	// there were.
	rules := "# parked\n" +
		"local6.*    @@first.example.net:514\n" +
		"local6.*    @@second.example.net:1514\n"

	got, active, ok := AdoptRule(rules)
	if !ok {
		t.Fatal("AdoptRule found nothing")
	}
	if got.Host != "first.example.net" {
		t.Errorf("host = %q, want the first rule", got.Host)
	}
	if active != 2 {
		t.Errorf("active = %d, want 2", active)
	}
}

func TestARuleThatNamesNoTargetIsNotAdopted(t *testing.T) {
	// The panel refused to write these, but the file is editable on the host and
	// a half rule must not become a receiver of nothing.
	for _, rule := range []string{
		"local6.* /var/log/somewhere.log",
		"local6.* @@",
		"local6.* @@host:notaport",
		"local6.* @@host:99999",
		"local6.* @:514",
	} {
		if _, _, ok := AdoptRule(rule); ok {
			t.Errorf("AdoptRule(%q) was adopted", rule)
		}
	}
}
