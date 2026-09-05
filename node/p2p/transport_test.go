package p2p_test

import (
	"crypto/ed25519"
	"net"
	"sync"
	"testing"
	"time"

	"zycord/core/types"
	"zycord/node/p2p"
	"zycord/spec"
)

// The transport is TLS 1.3 from the standard library, so what is worth testing
// here is not the cryptography — it is that peer *identity* is established and
// that the inbound limit actually binds.

func TestConnectionEstablishesPeerIdentity(t *testing.T) {
	server, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	client, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}

	ln, err := server.Listen("127.0.0.1:0", 4)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan *p2p.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()

	out, err := client.Dial(ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	in := <-accepted
	if in == nil {
		t.Fatal("the listener did not accept")
	}
	defer in.Close()

	// Each side must have learned the other's key, and only the other's.
	if !ed25519.PublicKey(out.PeerKey).Equal(server.PublicKey()) {
		t.Fatal("the dialler did not learn the server's identity")
	}
	if !ed25519.PublicKey(in.PeerKey).Equal(client.PublicKey()) {
		t.Fatal("the listener did not learn the dialler's identity")
	}
	if ed25519.PublicKey(out.PeerKey).Equal(client.PublicKey()) {
		t.Fatal("a node learned its own key as the peer's")
	}

	// And messages survive the round trip intact.
	payload := []byte("certificate bytes would go here")
	if err := out.Send(p2p.KindCertificate, payload); err != nil {
		t.Fatal(err)
	}
	kind, got, err := in.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if kind != p2p.KindCertificate || string(got) != string(payload) {
		t.Fatalf("received (%v, %q), want (certificate, %q)", kind, got, payload)
	}
}

// TestAcceptedConnectionsAreNotBlockedByASilentPeer is the accept stall's first
// half. A connection that completes the TCP handshake and then sends nothing
// must not be able to block Accept from ever returning a connection that does
// complete its handshake — before the fix, the single shared accept goroutine
// ran the TLS handshake inline with no deadline, so this one silent socket
// parked inbound connectivity for the whole process, for the cost of one
// SYN/ACK.
func TestAcceptedConnectionsAreNotBlockedByASilentPeer(t *testing.T) {
	server, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := server.Listen("127.0.0.1:0", 4)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// A silent connection: completes the TCP handshake and then sends
	// nothing, ever.
	silent, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()

	accepted := make(chan *p2p.Conn, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()

	// A well-behaved peer dials after the silent one is already sitting with
	// the listener. If the silent connection can block Accept, this one is
	// never handed back — and the dial itself, bounded to 5s, is the first
	// thing that would time out.
	client, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	honest, err := client.Dial(ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("an honest peer could not connect while a silent connection was "+
			"present: %v", err)
	}
	defer honest.Close()

	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("a silent connection blocked Accept from ever returning an honest " +
			"peer's connection")
	}
}

// TestSilentConnectionsCannotStarveAnHonestPeer is the trade-off that fix
// introduced and the round-2 cap half-closed, closed the rest of the way.
//
// Moving the handshake off the shared accept goroutine stopped one silent
// connection from blocking every accept, but nothing then bounded how many
// handshakes could be in flight *in total* — only how many one address group
// could hold (perSource+reserve), so each additional group an attacker
// controlled pinned more goroutines and file descriptors with no ceiling on
// the sum. A global cap bounds that. A global cap that *refuses* at the
// ceiling, however, hands the stall straight back: hold the cap full of silent
// connections and every honest peer is locked out for as long as the flood
// lasts, which is "one silent TCP connection halts all inbound accepts" again
// with a larger constant in front of it. Measured on that revision, a peer
// offering a real TLS handshake against a held cap got EOF.
//
// So the cap preempts the oldest handshake still in flight instead. This is
// the property that buys: silent connections holding the entire cap, and an
// honest peer still gets in — repeatedly, not once.
//
// perSource is set generously above the cap under test: every dial here comes
// from 127.0.0.1, one address group, so the per-group budget must not be what
// decides anything this test is about.
func TestSilentConnectionsCannotStarveAnHonestPeer(t *testing.T) {
	server, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := server.Listen("127.0.0.1:0", 100)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ln.SetMaxHandshakes(5)

	accepted := make(chan *p2p.Conn, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()

	// Silent connections: complete the TCP handshake and then send nothing,
	// each holding a handshake goroutine open until handshakeTimeout.
	for i := 0; i < 5; i++ {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("silent connection %d: %v", i, err)
		}
		defer c.Close()
	}
	// Let acceptRaw pick all five up and fill the cap. Each iteration is
	// non-blocking, so this is generous rather than necessary.
	time.Sleep(300 * time.Millisecond)

	// Five honest peers in a row, every one of them arriving at a cap that is
	// already full. All five must complete a real TLS handshake and reach
	// Accept — one getting through would not distinguish a working policy
	// from a lucky timeout.
	for i := 0; i < 5; i++ {
		client, err := p2p.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		conn, err := client.Dial(ln.Addr().String(), 3*time.Second)
		if err != nil {
			t.Fatalf("honest peer %d could not connect while %d silent connections held the "+
				"global handshake cap (per-group budget had 95 slots free): %v — refused=%d, "+
				"preempted=%d. This is the stall's symptom, priced at the cap instead of at one socket.",
				i, 5, err, ln.Refused(), ln.Preempted())
		}
		defer conn.Close()
		select {
		case <-accepted:
		case <-time.After(2 * time.Second):
			t.Fatalf("honest peer %d completed its TLS handshake but was never delivered to "+
				"Accept while the handshake cap was held by silent connections", i)
		}
	}

	if ln.Preempted() == 0 {
		t.Fatal("no handshake was preempted, so the cap under test was never actually " +
			"reached: this test proved nothing about behaviour at the cap")
	}
}

// TestInboundLimitBindsPerSource is half of M2-G4: one origin must not be able
// to fill the inbound slots and crowd everyone else out.
func TestInboundLimitBindsPerSource(t *testing.T) {
	server, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := server.Listen("127.0.0.1:0", 2)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c
		}
	}()

	// Every dial comes from 127.0.0.1, so they are all one source group. The
	// third should be refused: the listener closes it, and the dialler sees the
	// connection die rather than carrying traffic.
	var live []*p2p.Conn
	defer func() {
		for _, c := range live {
			c.Close()
		}
	}()
	var refused int
	for i := 0; i < 5; i++ {
		client, err := p2p.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		c, err := client.Dial(ln.Addr().String(), 2*time.Second)
		if err != nil {
			refused++
			continue
		}
		// A connection the listener dropped fails on first use.
		c.SetDeadline(time.Now().Add(time.Second))
		if err := c.Send(p2p.KindGetPeers, nil); err != nil {
			refused++
			c.Close()
			continue
		}
		if _, _, err := c.Receive(); err != nil {
			refused++
			c.Close()
			continue
		}
		live = append(live, c)
	}
	if refused == 0 {
		t.Fatal("a single source held every inbound slot; the per-source limit does not bind")
	}
}

// TestSendDeadlineBoundsAWriteToAPeerThatNeverReads is the write deadline's
// core guarantee: SendDeadline actually stops a write, rather than merely
// accepting a deadline value nothing enforces. net.Pipe is fully synchronous —
// a write blocks until a matching read consumes it — so a peer that never reads
// makes every write block until something bounds it.
func TestSendDeadlineBoundsAWriteToAPeerThatNeverReads(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	conn := &p2p.Conn{Conn: server, Addr: "peer:1"}

	start := time.Now()
	err := conn.SendDeadline(p2p.KindGetPeers, nil, time.Now().Add(300*time.Millisecond))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a write to a peer that never reads succeeded: net.Pipe is " +
			"unbuffered, so this could only happen if no deadline was actually " +
			"applied to the write")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("the write took %v to time out against a 300ms deadline: the "+
			"deadline was not applied to this write", elapsed)
	}
}

// TestConcurrentSendsDoNotInterleave exercises exactly the shape that named it:
// Broadcast is reachable from every serve goroutine's forward path and from
// the miner's announce calls at once, and a reply can land on the same
// connection at the same moment. SendDeadline's fix is that a write's
// deadline is set atomically with the write, under the same lock — this
// proves frames survive concurrent callers intact, which they could not if
// the lock were ever released between setting a deadline and using it, since
// a torn or reordered write would corrupt the frame stream immediately.
func TestConcurrentSendsDoNotInterleave(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	conn := &p2p.Conn{Conn: server, Addr: "peer:1"}
	reader := &p2p.Conn{Conn: client}

	const goroutines = 8
	const perGoroutine = 10
	const total = goroutines * perGoroutine

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				conn.SendDeadline(p2p.KindGetPeers, []byte{byte(g), byte(i)},
					time.Now().Add(5*time.Second))
			}
		}(g)
	}

	got := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for got < total {
			if _, payload, err := reader.Receive(); err != nil || len(payload) != 2 {
				return
			}
			got++
		}
	}()

	wg.Wait()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	if got != total {
		t.Fatalf("received %d intact frames, want %d: concurrent SendDeadline calls "+
			"corrupted the stream, which a write and its deadline racing under "+
			"different locks could produce", got, total)
	}
}

func TestFrameRejectsOversizedAndUnknownMessages(t *testing.T) {
	// An oversized frame must be refused before anything is allocated.
	huge := make([]byte, 0)
	if err := p2p.Frame(nopWriter{}, p2p.KindCertificate, huge); err != nil {
		t.Fatal(err)
	}
	// The read side is where a hostile peer sends the length, so that is the
	// side that matters: a claimed length beyond the limit must be refused
	// without reading the body.
	bad := []byte{0xff, 0xff, 0xff, 0xff, byte(p2p.KindCertificate)}
	if _, _, err := p2p.ReadFrame(bytesReader(bad)); err == nil {
		t.Fatal("an oversized frame was accepted")
	}
	unknown := []byte{0, 0, 0, 0, 200}
	if _, _, err := p2p.ReadFrame(bytesReader(unknown)); err == nil {
		t.Fatal("an unknown message kind was accepted")
	}
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

type sliceReader struct {
	b []byte
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, errEOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

var errEOF = errorString("eof")

type errorString string

func (e errorString) Error() string { return string(e) }

func bytesReader(b []byte) *sliceReader { return &sliceReader{b: b} }

// TestBlockByteCapacityFitsChunkedTransfer is the check that keeps a consensus
// rule and the transport's constants from drifting apart in the one direction
// that partitions the network.
//
// `block_byte_capacity` is the ceiling a block's encoded size may reach as the
// elastic sequential target grows (whitepaper §8.1, params.BlockByteLimit). A
// block travels as chunks (wire.go), so the bound the transport imposes is not
// one frame but MaxBlockChunks × BlockChunkBytes. If the consensus ceiling ever
// exceeded that, the result is not a rejected block — it is a block every node
// agrees is valid and no node can transmit. The producer holds a chain nobody
// can fetch, and after genesis that is a permanent partition no soft change
// repairs.
//
// The two numbers live in different layers on purpose: consensus cannot import
// the transport, and the transport must not get a vote on consensus. This test
// is the only place they meet, which is why an era re-pin of the byte capacity
// and the node release that carries it both have to come here.
//
// The set is spec.Networks() and never a list written out here, because a
// network this test does not cover is a network it cannot fail for. The values
// are identical across the three sets today, so a hand-written {mainnet,
// devnet} left no live gap — but the assertions exist to fail loudly on an era
// re-pin, and a re-pin arrives one parameter file at a time. Reading the
// embedded list also means a fourth network added to spec/ is covered on the
// commit that adds it rather than on the commit that remembers this test
// (the same argument TestEveryEmbeddedNetworkHasAPinnedGenesis makes).
func TestBlockByteCapacityFitsChunkedTransfer(t *testing.T) {
	networks := spec.Networks()
	if len(networks) < 3 {
		t.Fatalf("spec.Networks() returned %v: this test covers whatever spec/ embeds, "+
			"so a shrinking list silently narrows it", networks)
	}
	for _, name := range networks {
		p, err := spec.ParamsFor(name)
		if err != nil {
			t.Fatal(err)
		}
		if p.BlockByteCapacity > p2p.MaxBlockChunks*p2p.BlockChunkBytes {
			t.Fatalf("%s: block_byte_capacity %d exceeds the chunked-transfer ceiling %d; a block "+
				"at the consensus ceiling would be unsendable",
				name, p.BlockByteCapacity, p2p.MaxBlockChunks*p2p.BlockChunkBytes)
		}
		// And it must not exceed it by more than the pair's own slack. A
		// ceiling the block rules cannot reach is not headroom: it is a claim
		// a peer can make and this node must account for, and at the
		// inherited MaxBlockChunks of 256 that claim was 1 GiB against an
		// 8 MB block. Bounding it at twice the chunks a capacity block
		// needs is what makes an era re-pin raise the transport constants in
		// the release that carries it, rather than find the room already
		// there.
		chunksForCapacity := (p.BlockByteCapacity + p2p.BlockChunkBytes - 1) / p2p.BlockChunkBytes
		if p2p.MaxBlockChunks > 2*chunksForCapacity {
			t.Fatalf("%s: MaxBlockChunks %d is more than twice the %d chunks a block at "+
				"block_byte_capacity %d needs; the transport ceiling %d admits a transfer "+
				"no valid block can be",
				name, p2p.MaxBlockChunks, chunksForCapacity, p.BlockByteCapacity,
				p2p.MaxBlockChunks*p2p.BlockChunkBytes)
		}
		// Every chunk must itself fit a frame, or the chunking is a bound on
		// paper only.
		if p2p.BlockChunkBytes+64 > p2p.MaxMessageBytes {
			t.Fatalf("a full block chunk plus its envelope does not fit a frame")
		}
		// And the ceiling must actually be reachable by growth, or the clamp is
		// hiding a misconfiguration rather than bounding one.
		if p.BlockByteCapacity < p.BlockByteLimitGenesis {
			t.Fatalf("%s: block_byte_capacity %d is below the genesis byte ceiling %d",
				name, p.BlockByteCapacity, p.BlockByteLimitGenesis)
		}
		// The same pairing, one layer up: an announcement carries one id per
		// certificate, so it must cover the most certificates a valid block
		// can reach. That bound is the consensus ceiling at the maximal
		// target, MaxCertsPerBlock(SeqGasCapacity) — not CertListCapacity,
		// which is sized as merkle headroom for era re-pins (its note in
		// spec/params.json) and sits far above anything a block under the
		// current capacities can hold. When an era re-pin raises the
		// capacities, this recomputes, and the release that carries the
		// re-pin fails here until the announcement bounds are raised with it.
		reachable := p.MaxCertsPerBlock(p.SeqGasCapacity)
		if reachable > p2p.MaxAnnouncedCerts {
			t.Fatalf("%s: a block can hold %d certificates but MaxAnnouncedCerts is %d; a full "+
				"block could not be announced", name, reachable, p2p.MaxAnnouncedCerts)
		}
		if announce := types.HeaderSize + 4 + 32*reachable; announce > p2p.MaxMessageBytes {
			t.Fatalf("%s: a full block's announcement is %d bytes against a %d-byte frame",
				name, announce, p2p.MaxMessageBytes)
		}
	}
}
