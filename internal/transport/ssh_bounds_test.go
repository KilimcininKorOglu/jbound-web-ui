package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// floodServer is an SSH server that answers every command with a stream of the
// given length. It exists because the size of a remote answer is chosen by the
// remote side, and that is the case this file is about.
type floodServer struct {
	address string
	hostKey string

	// stdout and stderr are how many bytes one command answers with.
	stdout int
	stderr int

	// silent makes the server answer no global request at all, which is what a
	// flow dropped without an RST and a wedged peer both look like.
	silent bool
}

func startFloodServer(t *testing.T, stdout, stderr int) *floodServer {
	t.Helper()

	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("cannot generate the host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatalf("cannot build the host signer: %v", err)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	server := &floodServer{
		address: listener.Addr().String(),
		hostKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
		stdout:  stdout,
		stderr:  stderr,
	}

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go server.serve(conn, config)
		}
	}()
	return server
}

func (f *floodServer) serve(conn net.Conn, config *ssh.ServerConfig) {
	sshConn, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		conn.Close()
		return
	}
	defer sshConn.Close()
	if f.silent {
		// Drain without replying. The connection stays open and answers
		// nothing, which is the case a keepalive exists to catch.
		go func() {
			for range requests {
			}
		}()
	} else {
		go ssh.DiscardRequests(requests)
	}

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		channel, channelRequests, acceptErr := newChannel.Accept()
		if acceptErr != nil {
			return
		}
		go f.session(channel, channelRequests)
	}
}

// session answers the first exec request with the configured stream.
func (f *floodServer) session(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	for request := range requests {
		if request.WantReply {
			_ = request.Reply(request.Type == "exec", nil)
		}
		if request.Type != "exec" {
			continue
		}

		flood(channel, f.stdout)
		flood(channel.Stderr(), f.stderr)
		_ = channel.CloseWrite()
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
		return
	}
}

// flood writes count bytes of valid base64, so a read that is refused is
// refused for its size rather than for its shape.
func flood(w io.Writer, count int) {
	const block = 32 << 10

	chunk := []byte(strings.Repeat("A", block))
	for written := 0; written < count; {
		size := min(block, count-written)
		n, err := w.Write(chunk[:size])
		if err != nil {
			return
		}
		written += n
	}
}

// transportTo builds a transport pointed at the test server.
func transportTo(t *testing.T, server *floodServer) *SSHTransport {
	t.Helper()

	host, port, err := net.SplitHostPort(server.address)
	if err != nil {
		t.Fatalf("cannot split %s: %v", server.address, err)
	}

	cfg := validConfig()
	cfg.Host = host
	cfg.Port = mustAtoi(t, port)
	cfg.KeyPath = writeTestKey(t)
	cfg.HostKey = server.hostKey
	cfg.ConnectTimeout = 5 * time.Second
	cfg.CommandTimeout = 30 * time.Second

	transport, err := NewSSH(cfg)
	if err != nil {
		t.Fatalf("cannot build the transport: %v", err)
	}
	t.Cleanup(func() { transport.Close() })
	return transport
}

func TestAServerCannotChooseHowMuchThePanelAllocates(t *testing.T) {
	// The panel used to buffer whatever came back. A server holding a huge
	// file at the configured path, or one that simply never stops writing,
	// decided how much memory the panel host gave up, and the refresher runs
	// several of them at once.
	server := startFloodServer(t, maxStdoutBytes+(64<<10), 0)
	transport := transportTo(t, server)

	_, _, err := transport.ReadHostEntries(context.Background())
	if !errors.Is(err, ErrRemoteOutput) {
		t.Fatalf("read error = %v, want an output the panel refuses", err)
	}
	if !strings.Contains(err.Error(), "more than") {
		t.Errorf("the failure does not say what was wrong: %v", err)
	}
}

func TestAnOversizedReadIsRefusedRatherThanTruncated(t *testing.T) {
	// A base64 string that is cut short still decodes. A silently shortened
	// file would read as a complete one, and the next write would replace the
	// real file on the server with it.
	server := startFloodServer(t, maxStdoutBytes+1024, 0)
	transport := transportTo(t, server)

	data, _, err := transport.ReadHostEntries(context.Background())
	if err == nil {
		t.Fatalf("the read returned %d bytes instead of failing", len(data))
	}
	if len(data) != 0 {
		t.Errorf("the read returned %d bytes alongside its failure", len(data))
	}
}

func TestNoisyDiagnosticsDoNotFailACommand(t *testing.T) {
	// stderr carries diagnostics, and an audit row shows four hundred
	// characters of it. Dropping the rest costs nothing, and failing over it
	// would turn a loud but successful reload into an error.
	server := startFloodServer(t, 0, maxStderrBytes*2)
	transport := transportTo(t, server)

	if _, err := transport.Reload(context.Background()); err != nil {
		t.Fatalf("a noisy reload failed: %v", err)
	}
}

// openConnection makes the transport dial, so the keepalive has something to
// ping. A transport with no connection is left alone on purpose.
func openConnection(t *testing.T, client *SSHTransport) {
	t.Helper()

	if _, _, err := client.ReadHostEntries(context.Background()); err != nil {
		t.Fatalf("cannot open the connection: %v", err)
	}
}

func TestAPeerThatNeverAnswersDoesNotHoldTheKeepalive(t *testing.T) {
	// A connection dropped without an RST answers nothing, which is the exact
	// case the keepalive exists to catch. Waiting for that answer used to be
	// waiting for ever, with the transport mutex held.
	server := startFloodServer(t, 0, 0)
	server.silent = true
	client := transportTo(t, server)
	openConnection(t, client)

	done := make(chan error, 1)
	go func() { done <- client.keepalive(200 * time.Millisecond) }()

	select {
	case err := <-done:
		if !errors.Is(err, ErrUnreachable) {
			t.Fatalf("keepalive = %v, want an unreachable server", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the keepalive never gave up")
	}

	// The connection is dropped, so the next operation dials again rather than
	// speaking down a line nobody answers.
	client.mu.Lock()
	held := client.client
	client.mu.Unlock()
	if held != nil {
		t.Error("the wedged connection was kept")
	}
}

func TestOneWedgedServerDoesNotStopTheSweep(t *testing.T) {
	// sweep used to ping one server after another from the maintenance loop.
	// One connection that never answered stopped every other server from ever
	// being swept again.
	wedged := startFloodServer(t, 0, 0)
	wedged.silent = true

	pool := NewPool(context.Background(), func() time.Duration { return time.Hour })
	t.Cleanup(pool.Close)
	pool.pingTimeout = 200 * time.Millisecond

	for id, server := range []*floodServer{wedged, wedged, wedged, startFloodServer(t, 0, 0)} {
		client := transportTo(t, server)
		openConnection(t, client)
		pool.mu.Lock()
		pool.entries[int64(id+1)] = &poolEntry{
			transport: client, config: client.cfg, lastUsed: time.Now()}
		pool.mu.Unlock()
	}

	start := time.Now()
	pool.sweep()
	// Three wedged servers, one after another, would be three deadlines.
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("the sweep took %s, the servers were pinged one after another", elapsed)
	}
}
