//go:build integration

// Proves that an audit entry reaches a receiver over a real socket.
//
// The unit tests cover the CEF text, the framing and the cursor, but every one
// of them hands the sender a connection of its own. What they cannot show is
// the chain: an entry written through the audit logger lands in the database,
// the queue reads it back, and the bytes leave over a socket the operating
// system opened.
//
// The receiver is a listener inside the test rather than the sink container, so
// the assertion sees the bytes rather than a file it would have to poll on
// another machine.
//
// Run it with: make dev-itest

package siem_test

import (
	"bufio"
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"jbound/internal/audit"
	"jbound/internal/database"
	"jbound/internal/siem"
	"jbound/internal/store"
)

// forwardWindow is how long the receiver waits for the line. A test that fails
// here means nothing arrived at all.
const forwardWindow = 30 * time.Second

func TestGateAnAuditEntryReachesTheReceiver(t *testing.T) {
	ctx := context.Background()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot open the receiver: %v", err)
	}
	defer func() { _ = listener.Close() }()

	lines := make(chan string, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = connection.Close() }()

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

	db, err := database.Open(ctx, filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("cannot open the database: %v", err)
	}
	defer func() { _ = db.Close() }()

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("cannot read the receiver address: %v", err)
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		t.Fatalf("cannot read the receiver port: %v", err)
	}

	sender := siem.NewSender("panel.test",
		func() string { return siem.ProtocolTCP },
		func() string { return host },
		func() int { return port })
	defer func() { _ = sender.Close() }()

	rows := store.NewAuditLogs(db.DB)
	queue := siem.NewQueue(rows, store.NewSIEMCursor(db.DB), sender, "panel.test",
		func() bool { return true })

	// The first round places the cursor at the present, which is what keeps a
	// newly named receiver from being handed months of history. Nothing is sent
	// here, and everything after it is.
	queue.Drain(ctx)

	// The entry goes in the way the panel writes it, so the row the queue reads
	// back is the row a handler would have produced.
	logger := audit.NewLogger(rows)
	err = logger.Write(ctx, audit.Entry{
		UID: 1001, Username: "dnsadmin", Action: audit.ActionLogin,
		Details: "gate_forward_probe", IPAddress: "203.0.113.5",
	})
	if err != nil {
		t.Fatalf("cannot write the audit entry: %v", err)
	}

	queue.Drain(ctx)

	select {
	case line := <-lines:
		if !strings.Contains(line, "CEF:0|JBound|JBoundDNSPanel") {
			t.Errorf("the receiver got a line that is not CEF: %q", line)
		}
		if !strings.Contains(line, siem.Tag) {
			t.Errorf("the line carries no panel tag: %q", line)
		}
		if !strings.Contains(line, "suser=dnsadmin") {
			t.Errorf("the line names no user: %q", line)
		}
	case <-time.After(forwardWindow):
		t.Fatal("no event reached the receiver")
	}
}
