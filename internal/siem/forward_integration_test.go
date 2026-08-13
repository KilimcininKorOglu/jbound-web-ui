//go:build integration

// Proves that a forwarded event leaves the panel host.
//
// The unit tests cover the CEF text and the rule syntax. What they cannot show
// is the chain behind them: the panel writes to the local syslog socket, the
// daemon reads its own configuration, and a receiver somewhere else gets a
// line. Every part of that runs outside the process.
//
// The receiver here is a listener inside the test rather than the sink
// container, so the assertion sees the bytes rather than a file it would have
// to poll on another machine.
//
// Run it with: make dev-itest

package siem_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"unbound-web/internal/audit"
	"unbound-web/internal/config"
	"unbound-web/internal/siem"
)

// forwardWindow is how long the receiver waits for the line.
//
// rsyslog reconnects on its own schedule after a restart, so the window is
// generous. A test that fails here means nothing arrived at all.
const forwardWindow = 45 * time.Second

func TestGateAForwardedEventLeavesTheHost(t *testing.T) {
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("cannot load the configuration: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot open the receiver: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	manager := siem.NewManager(cfg.RsyslogConfPath, cfg.SyslogLogPath,
		cfg.RsyslogValidateCmd, cfg.RsyslogRestartCmd, cfg.RsyslogStatusCmd)

	// The configuration of the container is restored afterwards, because the
	// stack keeps running after the tests do.
	previous, err := manager.Settings(context.Background())
	if err != nil {
		t.Fatalf("cannot read the current settings: %v", err)
	}
	t.Cleanup(func() {
		if err := manager.Save(context.Background(), previous.ForwardingRules); err != nil {
			t.Errorf("cannot restore the forwarding rules: %v", err)
		}
	})

	rule := fmt.Sprintf("local6.*    @@127.0.0.1:%d", port)
	if err := manager.Save(context.Background(), rule); err != nil {
		t.Fatalf("cannot write the forwarding rule: %v", err)
	}

	lines := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()

		_ = connection.SetReadDeadline(time.Now().Add(forwardWindow))
		reader := bufio.NewReader(connection)
		for {
			line, err := reader.ReadString('\n')
			if strings.Contains(line, "gate_forward_probe") {
				lines <- line
				return
			}
			if err != nil {
				return
			}
		}
	}()

	forwarder := siem.NewForwarder("panel.test")
	defer forwarder.Close()

	// The daemon reconnects on its own schedule, so the event is repeated
	// until the receiver has it or the window closes.
	deadline := time.After(forwardWindow)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	send := func() {
		err := forwarder.Forward(audit.Entry{
			UID: 1001, Username: "dnsadmin", Action: audit.ActionLogin,
			Details: "gate_forward_probe", IPAddress: "203.0.113.5",
		})
		if err != nil {
			t.Errorf("cannot forward the event: %v", err)
		}
	}
	send()

	for {
		select {
		case line := <-lines:
			if !strings.Contains(line, "CEF:0|JanBound|JanBoundDNSPanel") {
				t.Errorf("the receiver got a line that is not CEF: %q", line)
			}
			if !strings.Contains(line, "unbound-dns-panel") {
				t.Errorf("the line carries no panel tag: %q", line)
			}
			if !strings.Contains(line, "suser=dnsadmin") {
				t.Errorf("the line names no user: %q", line)
			}
			return
		case <-ticker.C:
			send()
		case <-deadline:
			t.Fatal("no forwarded event reached the receiver")
		}
	}
}
