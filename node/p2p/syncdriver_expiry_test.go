package p2p_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/p2p"
	"zycord/node/sync"
)

// The whole-attempt deadline used to accuse the peer it fired on.
//
// A joiner cold-syncing a chain longer than one attempt can carry ends every
// attempt the same way: the budget expires, the read in flight fails with an
// i/o timeout, and `sync.Fetch` — which cannot see the deadline and correctly
// does not try to — reports it in the only vocabulary it has, "peer will not
// serve a body for a header it advertised". The peer named there is the
// bootstrap node, and it served everything it was asked for right up to the
// moment the clock ran out.
//
// Nothing was ever *charged* for it (the same error carries ErrTransport and
// SyncPenalty exempts every transport fault), so this is a naming defect and
// the fix is a naming fix: reclassify at the driver, the only layer that knows
// the attempt's deadline, and keep the inner error so the score cannot move.
//
// haltingBodyPeer below is the field shape reduced to its essential: a peer
// that handshakes honestly, serves every header it is asked for, serves the
// first `serveBodies` bodies correctly, and then goes silent. It never errors
// and never closes, so the only thing that can end the attempt is the joiner's
// own budget.

// haltingBodyPeer serves sync honestly from src and then stops.
//
// After `serveBodies` body requests it either parks forever (silent, the
// expiry shape) or closes the connection (the sub-deadline transport shape a
// genuinely vanished peer produces). Returns the dialable address.
func haltingBodyPeer(t *testing.T, networkID types.Hash, src *chain.Chain,
	serveBodies int, silent bool) string {
	t.Helper()

	// The bodies this peer is willing to serve, indexed the way a request
	// names them. Built up front so the serving goroutine touches nothing the
	// test also touches.
	bodies := map[types.Hash][]byte{}
	for h := uint64(0); h <= src.Height(); h++ {
		blk, err := src.BlockAt(h)
		if err != nil {
			t.Fatalf("setup: reading block %d from the source chain: %v", h, err)
		}
		bodies[blk.Header.ID()] = blk.MarshalSSZ()
	}
	tipHeight, tipWork := src.Height(), src.TotalWork()

	id, err := p2p.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := id.Listen("127.0.0.1:0", 4)
	if err != nil {
		t.Fatal(err)
	}
	// hold parks the silent handler so it stays silent instead of returning
	// and closing the connection behind it — an immediate EOF is the one
	// answer that would make this test pass for the wrong reason, because EOF
	// arrives long before the deadline and must not be reclassified.
	hold := make(chan struct{})
	t.Cleanup(func() {
		close(hold)
		ln.Close()
	})

	headers := func(from uint64, count uint32) []types.Header {
		var out []types.Header
		for h := from; h <= src.Height() && len(out) < int(count); h++ {
			blk, err := src.BlockAt(h)
			if err != nil {
				break
			}
			out = append(out, blk.Header)
		}
		return out
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// The handshake has to succeed, or the attempt ends for a
				// reason this test is not about (ErrWrongNetwork).
				conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				if _, _, err := conn.Receive(); err != nil {
					return
				}
				hello := p2p.Hello{
					Protocol:  p2p.ProtocolVersion,
					NetworkID: networkID,
					Height:    tipHeight,
					Work:      tipWork.Bytes(),
				}
				if conn.Send(p2p.KindHello, hello.MarshalHello()) != nil {
					return
				}

				served := 0
				for {
					conn.SetReadDeadline(time.Now().Add(30 * time.Second))
					kind, payload, err := conn.Receive()
					if err != nil {
						return
					}
					switch kind {
					case p2p.KindGetHeaders:
						req, err := p2p.UnmarshalGetHeaders(payload)
						if err != nil {
							return
						}
						if conn.Send(p2p.KindHeaders,
							p2p.MarshalHeaders(headers(req.From, req.Count))) != nil {
							return
						}
					case p2p.KindGetBlock:
						if served >= serveBodies {
							if !silent {
								// The vanished-peer shape: the socket goes
								// away well inside the budget.
								return
							}
							// And now nothing, ever. No error, no close, no
							// junk — the peer simply stops, which is the only
							// way a peer can decline over this wire, and is
							// what leaves the joiner's own deadline as the
							// only thing that can end the attempt.
							<-hold
							return
						}
						req, err := p2p.UnmarshalGetBlock(payload)
						if err != nil {
							return
						}
						body, ok := bodies[req.ID]
						if !ok {
							return
						}
						chunk := p2p.BlockChunk{
							ID:    req.ID,
							Chunk: req.Chunk,
							Total: uint32(p2p.ChunkCount(len(body))),
							Data:  p2p.ChunkOf(body, int(req.Chunk)),
						}
						if conn.Send(p2p.KindBlock, chunk.MarshalBlockChunk()) != nil {
							return
						}
						if req.Chunk == chunk.Total-1 {
							served++
						}
					default:
						// Nothing else is expected on a dedicated sync
						// connection; ignoring it keeps the helper from
						// inventing behaviour the driver never asks for.
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// TestAnExpiredSyncAttemptDoesNotAccuseThePeer states it directly: the
// error a joiner reports when its own budget runs out must say so, and must
// not read as a withholding peer.
func TestAnExpiredSyncAttemptDoesNotAccuseThePeer(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, "source", p, key(t, 1).Persistent())
	source.mine(t, 8)

	victim := newNode(t, "victim", p, key(t, 2).Persistent())
	// Far below the 10-minute default, which a test must not wait for, and
	// which stays exactly 10 minutes in production — the deadline is a Node
	// field for precisely this.
	victim.node.SyncAttemptTimeout = 1500 * time.Millisecond

	addr := haltingBodyPeer(t, victim.chain.NetworkID(), source.chain, 3, true)

	start := time.Now()
	err := victim.node.SyncFrom(addr)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("setup: SyncFrom succeeded against a peer that stops serving " +
			"bodies partway, so no attempt expired and there is nothing to " +
			"classify")
	}
	// Anti-vacuity: the attempt must really have run to its budget, not
	// failed early for an unrelated reason. An EOF at a few milliseconds is
	// the shape that would make everything below pass without exercising the
	// expiry at all.
	if elapsed < victim.node.SyncAttemptTimeout {
		t.Fatalf("SyncFrom returned after %s, inside its own %s budget: the "+
			"failure under test is the budget expiring, and this one ended "+
			"before it could (err: %v)", elapsed, victim.node.SyncAttemptTimeout, err)
	}
	// And it must be the peer-accusing shape underneath, or the reclassified
	// error is being checked against an error that never accused anybody.
	if !errors.Is(err, sync.ErrBodyUnavailable) {
		t.Fatalf("setup: the expiry did not surface as a body-unavailable "+
			"report (%v), so this is not the misattribution under test", err)
	}

	if !errors.Is(err, p2p.ErrAttemptExpired) {
		t.Fatalf("a sync attempt that ran out of its own %s budget reported "+
			"%q. That names the bootstrap peer as withholding a body it "+
			"advertised, when the peer served every body it was asked for "+
			"until this node's clock ran out — and every joiner of a chain "+
			"longer than one attempt reads that line about the honest peer "+
			"it depends on.", victim.node.SyncAttemptTimeout, err)
	}

	// The reclassification is what an operator reads first, so it has to lead
	// rather than hide behind the accusation it replaces.
	if !strings.HasPrefix(err.Error(), p2p.ErrAttemptExpired.Error()) {
		t.Fatalf("the expiry is not the leading clause of %q: syncLoop logs "+
			"this error verbatim, so anything ahead of it is what the "+
			"operator actually sees", err)
	}

	// The height is the point of carrying one: a run of expiries on a long
	// cold sync is normal, and what distinguishes converging from stuck is
	// that this number moves. It is what the attempt *landed* — salvage keeps
	// the extending prefix — not what it asked for.
	want := victim.chain.Height()
	if !strings.Contains(err.Error(), "after reaching height "+strconv.FormatUint(want, 10)) {
		t.Fatalf("the expiry reports a height that is not the one this node "+
			"actually reached (%d): %v", want, err)
	}
	if want == 0 {
		t.Fatal("setup: the attempt landed no blocks at all, so the reported " +
			"height is trivially right and this peer is not the serve-then-halt " +
			"shape the field report describes")
	}

	// Nothing about the score may move. The inner error is kept with %w for
	// exactly this reason, and the ErrTransport exemption in SyncPenalty is
	// untouched (the body-refusal charge owns that guard).
	if !errors.Is(err, p2p.ErrTransport) {
		t.Fatalf("reclassifying dropped ErrTransport from %v: SyncPenalty's "+
			"exemption is keyed on it, so losing it would start charging an "+
			"honest bootstrap peer -10 per expiry", err)
	}
	if got := p2p.SyncPenalty(err); got != 0 {
		t.Fatalf("an expired attempt charged the peer %d points (err: %v): the "+
			"peer served everything it was asked for, and %d consecutive "+
			"expiries would ban the only source this node has",
			got, err, p2p.ScoreBanThreshold/got)
	}
}

// TestATransportFaultInsideTheBudgetIsNotAnExpiry is the other half, and the
// reason the classification is a test on the deadline rather than a blanket
// rename: a peer that genuinely went away mid-attempt must keep reading as a
// transport failure.
//
// Without it, "expired" would be the new name for every transport fault on
// this path, which would lose exactly the distinction that matters — and the
// unexplained 156-second abort that prompted it is the shape it would
// have mislabelled.
func TestATransportFaultInsideTheBudgetIsNotAnExpiry(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, "source", p, key(t, 1).Persistent())
	source.mine(t, 8)

	victim := newNode(t, "victim", p, key(t, 2).Persistent())
	// Far longer than this test's patience, so the budget cannot be what ends
	// the attempt: the peer's disappearance has to be.
	victim.node.SyncAttemptTimeout = 5 * time.Minute

	addr := haltingBodyPeer(t, victim.chain.NetworkID(), source.chain, 2, false)

	start := time.Now()
	err := victim.node.SyncFrom(addr)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("setup: SyncFrom succeeded against a peer that drops the " +
			"connection partway through the bodies")
	}
	if elapsed > 30*time.Second {
		t.Fatalf("setup: the attempt took %s, long enough that the 5-minute "+
			"budget is no longer obviously irrelevant to what ended it", elapsed)
	}
	if !errors.Is(err, p2p.ErrTransport) {
		t.Fatalf("setup: a dropped connection did not report a transport "+
			"fault (%v), so the branch under test is not the one reached", err)
	}
	if errors.Is(err, p2p.ErrAttemptExpired) {
		t.Fatalf("a peer that disappeared %s into a %s budget was reported as "+
			"the attempt reaching its time budget (%v): that reads the "+
			"operator's one signal backwards, telling them to wait longer "+
			"when the peer is gone",
			elapsed, victim.node.SyncAttemptTimeout, err)
	}
}
