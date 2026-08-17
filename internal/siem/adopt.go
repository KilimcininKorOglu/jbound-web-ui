package siem

import (
	"strconv"
	"strings"
)

// defaultSyslogPort is what a forwarding rule that names no port meant.
const defaultSyslogPort = 514

// Receiver is where the panel sends its trail.
type Receiver struct {
	Protocol string
	Host     string
	Port     int
}

// AdoptRule reads a receiver out of the rsyslog forwarding rules the panel used
// to write, and reports whether it found one.
//
// A panel that forwarded through rsyslog before this release has its collector
// named in that file and nowhere else. Without this the upgrade would leave the
// receiver off, the trail would stop reaching the collector, and nobody would be
// told until somebody went looking for events that were never sent.
//
// The first active rule wins. A file with several is a file the operator has to
// look at, and guessing which one they meant would be worse than taking the
// first and saying so.
func AdoptRule(rules string) (Receiver, int, bool) {
	var (
		found     Receiver
		active    int
		haveFound bool
	)

	for line := range strings.SplitSeq(rules, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		active++

		receiver, ok := parseRule(trimmed)
		if ok && !haveFound {
			found, haveFound = receiver, true
		}
	}
	return found, active, haveFound
}

// parseRule reads one rsyslog forwarding rule.
//
// Two at signs meant TCP and one meant UDP, which is the only place that
// distinction was ever written down.
func parseRule(rule string) (Receiver, bool) {
	_, target, found := strings.Cut(rule, "@")
	if !found {
		return Receiver{}, false
	}

	protocol := ProtocolUDP
	if after, isTCP := strings.CutPrefix(target, "@"); isTCP {
		protocol = ProtocolTCP
		target = after
	}

	target = strings.TrimSpace(target)
	if target == "" {
		return Receiver{}, false
	}

	host, portText, hasPort := strings.Cut(target, ":")
	if host == "" {
		return Receiver{}, false
	}

	port := defaultSyslogPort
	if hasPort {
		parsed, err := strconv.Atoi(portText)
		if err != nil || parsed < 1 || parsed > 65535 {
			return Receiver{}, false
		}
		port = parsed
	}
	return Receiver{Protocol: protocol, Host: host, Port: port}, true
}
