package p2p

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"sort"
	gosync "sync"
	"time"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/sync"
)

// writeTimeout bounds every write this node makes to a peer connection: the
// initial handshake, a reply, and each target of a broadcast fan-out.
//
// Without it, a peer that stops reading — deliberately or not — pins the
// goroutine writing to it, and on the reply path, the reply payload behind it
// (up to MaxMessageBytes) along with it, indefinitely.
const writeTimeout = 10 * time.Second

// Node is the connection manager: it dials, accepts, runs a message loop per
// peer, and gossips.
//
// Everything adversarial about it lives in two places that are deliberately
// small. Outbound targets come from PeerStore.SelectDiverse, so one hosting
// range fills one slot; inbound is bounded per source by the Listener. Those
// two, plus the persisted peer store, are the whole eclipse defence (M2-G4),
// and each is a handful of lines precisely so that a reader can check them.
// DefaultMaxOutbound and DefaultMaxInbound are the connection-set sizes
// NewNode installs, named rather than typed inline because a package constant
// is derived from them: DefaultMaxUnheldKeyEpochsPerNode (engine.go) is the
// size of the concurrent connection set multiplied by what one payer may spend,
// and a derivation that reads a literal is a derivation nobody can check. The
// LIVE ceiling reads the MaxInbound and MaxOutbound fields below rather than
// these constants — publishConnectionSet is how it gets them — so these two
// name only what an unconfigured node starts at.
const (
	DefaultMaxOutbound = 8
	DefaultMaxInbound  = 32
)

type Node struct {
	Identity *Identity
	Engine   *Engine
	Peers    *PeerStore
	// MaxOutbound and MaxInbound bound the connection set. Being
	// under-connected is its own eclipse risk, so the dialler keeps trying to
	// reach MaxOutbound.
	MaxOutbound int
	MaxInbound  int
	// Bootstrap is the initial peer list. It is deliberately data rather than
	// code: a bootstrap list baked into a binary is a list nobody can change
	// when one of its entries goes bad, and — for an anonymous project — a map
	// of whoever compiled it.
	//
	// **This package still holds none, and that is the part of the rule that
	// did not move.** What changed is one layer up: cmd/zycordd now supplies a
	// default for the public testnet when the operator names nothing, so the
	// sentence above is a statement about THIS package rather than about every
	// binary built from the tree. The distinction is worth keeping sharp — a
	// library that carried addresses would impose them on every embedder,
	// including networks it has never heard of, whereas a client's default is
	// one the client's own flags can refuse.
	//
	// Entries may be `host:port` or `ip:port`; names are resolved once at Start
	// and expanded to at most maxBootstrapAddrs targets each. A name is what
	// makes an entry repairable without a release, so a caller supplying
	// defaults should prefer one.
	Bootstrap []string
	// DialInterval is how often the dialler tops up connections.
	DialInterval time.Duration
	// GetPeersInterval is how often this node asks one peer for addresses. Zero
	// or negative disables asking entirely, which is the behaviour every
	// revision before this one had.
	//
	// It is deliberately not DialInterval. The dial loop runs on the order of
	// seconds because a missing connection is a liveness problem; a missing
	// *address* is not, and the reply is the most expensive frame in the
	// protocol to build. One ask per interval per node, to one peer, is the
	// whole of the send side — see askForPeers.
	GetPeersInterval time.Duration
	// SyncInterval is how often the node checks whether a peer has more work
	// and, if so, catches up with it.
	SyncInterval time.Duration
	// SyncAttemptTimeout bounds one SyncFrom call's whole wall-clock run
	// against one peer, on top of and independent of the per-read deadlines
	// inside it (syncdriver.go). Zero falls back to syncAttemptTimeout's
	// default; NewNode sets that default explicitly so the zero value is only
	// ever seen by a Node built some other way.
	SyncAttemptTimeout time.Duration
	// WithholdInterval is how often withheld blocks are re-evaluated against
	// the local clock. It is the re-evaluation trigger the future-time rule
	// needs: a block held because it is early becomes judgeable when nothing
	// happens, and no message arrives to say so. One second, because the rule's
	// resolution is one second.
	WithholdInterval time.Duration
	Logger           *log.Logger

	listener *Listener

	// skew is reportClockSkew's rate-limiting and episode state. Owned by
	// withholdLoop and read by nothing else — the one goroutine that calls
	// reportClockSkew — so it needs no lock; the counters it compares against
	// live on the Engine behind the Engine's own mutex.
	skew skewReportState

	mu    gosync.Mutex
	conns map[string]*Conn
	// outboundTargets records which connections this node initiated, which is
	// what distinguishes core from periphery in Topology.
	//
	// It is also this node's dial budget: dialTargets asks for
	// MaxOutbound - len(outboundTargets) new targets, so an entry that is
	// claimed and never given back is a dial slot lost for the life of the
	// process. In production it is claimed in exactly one place
	// (reserveOutboundTarget) and given back in exactly one place (retire);
	// see serve for why the release is a defer installed before any gate that
	// can refuse, and retire for why it shares a critical section with the
	// n.conns deletion. Tests in this package write it directly.
	outboundTargets map[string]bool
	quit            chan struct{}
	wg              gosync.WaitGroup
	// syncTried records the order in which peers were last asked to serve sync,
	// which is what makes peer selection a rotation rather than a ranking.
	//
	// A sequence number and not a timestamp, deliberately. The rotation
	// needs a strict order over "who has waited longest", and a wall clock does
	// not give one: its resolution is a platform detail, and on a coarse clock
	// two stamps taken either side of a round compare *equal*, which sends the
	// choice to the height tie-break. That is the argmax-over-unverified-claims
	// starvation vector SyncCandidates exists to avoid, reappearing as a
	// property of the clock rather than of the policy. A counter cannot tie
	// unless the policy meant it to.
	syncTried map[string]uint64
	// syncSeq is the last sequence number handed out. Every entry in syncTried
	// carries one, and larger means more recently placed at the back.
	syncSeq uint64
	// syncBodies retains bodies across sync attempts. It lives on the node
	// rather than on the connection because the connection is the thing that
	// keeps dying: a reorg must be applied whole, so without something that
	// outlives one socket, a catch-up over a lossy link restarts from zero
	// every time and a node far enough behind never arrives.
	syncBodies *sync.BodyCache
	// syncInbox is where a sync attempt running over a *shared* gossip
	// connection waits for its answer, keyed by connection address.
	//
	// It exists because a peer that dialled this node and advertises no listen
	// address cannot be dialled back, so the dedicated sync connection
	// wire.md §12 describes is not available against it. Sync over the gossip
	// connection instead needs the frame routed from the one goroutine reading
	// that socket (serve) to the one goroutine that asked for it — see
	// deliverSyncResponse and sharedTransport in syncdriver.go.
	syncInbox map[string]*syncMailbox
	// rng drives dial jitter. Seeded per node so a soak run is reproducible.
	rng *rand.Rand
	// selfAddrs are addresses at which this node recently authenticated as
	// itself, mapped to the instant the exclusion expires.
	//
	// It exists so that the proof is kept for a while. Without it the key
	// guard in the transport refuses the same address again on the next dial
	// round, and every round after: correct each time, and a dial attempt
	// spent on this process forever. Feeding them into the dial selector's
	// exclusion set instead makes the address structurally not a candidate,
	// and — because exclusion is applied before the diversity and per-source
	// budgets are counted — the slot is handed to a real peer in the same
	// round rather than left empty.
	//
	// It is a deadline and not a bool because the entry is not the
	// unforgeable fact it looks like. A self-connection can be *arranged* by
	// someone who holds none of this node's secrets: an on-path attacker
	// that answers an honest peer's address and splices the stream to this
	// node's own listener produces a handshake that genuinely completes
	// against this node's own key — CertificateVerify and all — so the
	// verdict is correct about the connection and wrong about the address.
	// A permanent entry would then delete an honest peer from this node's
	// dial set for the life of the process, outliving the attacker's
	// presence on the path: a transient capability converted into a durable
	// eclipse assist, which is strictly more than dropping that address's
	// packets buys (a retryable MarkFailed). Bounding it is the only
	// available answer, because at the identity layer a relay to ourselves
	// *is* a self-connection and no comparison can tell the two apart.
	//
	// The trade is asymmetric in the direction that favours forgetting. Too
	// short costs one dial attempt per genuinely-self address per window —
	// against a DialInterval of seconds, noise. Too long is an honest peer
	// this node will not call.
	selfAddrs map[string]time.Time
	// dialFn overrides Identity.Dial for one dial round. Nil in production and
	// set only by tests; see Node.dial.
	dialFn func(addr string, timeout time.Duration) (*Conn, error)
	// evicted counts admitted inbound connections given up to admit a newer
	// arrival at capacity. Guarded by mu; see Evicted and
	// inboundVictimLocked.
	evicted int64
	// nextGetPeers is the instant the next get-peers becomes due. The
	// zero value is due immediately and is meant to be: a node that has just
	// made its first outbound connection is the node with the thinnest
	// address set it will ever have, and waiting a full interval to ask is
	// waiting during the only window in which the bootstrap list is the
	// entire eclipse surface.
	nextGetPeers time.Time
}

// NewNode returns a connection manager.
func NewNode(id *Identity, engine *Engine, peers *PeerStore, seed int64) *Node {
	n := &Node{
		Identity:           id,
		Engine:             engine,
		Peers:              peers,
		MaxOutbound:        DefaultMaxOutbound,
		MaxInbound:         DefaultMaxInbound,
		DialInterval:       2 * time.Second,
		GetPeersInterval:   DefaultGetPeersInterval,
		SyncInterval:       3 * time.Second,
		SyncAttemptTimeout: syncAttemptTimeout,
		WithholdInterval:   time.Second,
		conns:              map[string]*Conn{},
		syncTried:          map[string]uint64{},
		outboundTargets:    map[string]bool{},
		selfAddrs:          map[string]time.Time{},
		quit:               make(chan struct{}),
		rng:                rand.New(rand.NewSource(seed)),
	}
	n.publishConnectionSet()
	return n
}

// Listen starts accepting connections.
func (n *Node) Listen(addr string) error {
	ln, err := n.Identity.Listen(addr, 3)
	if err != nil {
		return err
	}
	n.listener = ln
	n.wg.Add(1)
	go n.acceptLoop()
	return nil
}

// ListenAddr returns the bound address, or "" if not listening.
func (n *Node) ListenAddr() string {
	if n.listener == nil {
		return ""
	}
	return n.listener.Addr().String()
}

// bootstrapResolveTimeout bounds one DNS lookup of a --peers entry. A resolver
// that never answers is a resolver this node waits on, and the wait used to be
// on Start's own goroutine with no deadline at all.
const bootstrapResolveTimeout = 5 * time.Second

// maxBootstrapAddrs bounds how many dial targets one --peers entry may expand
// into. A name is answered by a resolver, and a resolver is not necessarily
// the operator's.
const maxBootstrapAddrs = 8

// resolveBootstrap turns one --peers entry into the dial targets it names.
//
// The peer store holds IP-hosted addresses only: an address that is not an IP
// has no /16, so it has no diversity group, and a store that accepts one
// accepts an attacker minting a fresh group per invented string. But
// docs/RUNNING.md documents the operator-facing bootstrap flag with hostnames
// —
//
//	zycordd --dir ./data --peers node1.example:9421,node2.example:9421
//
// — and an operator's own bootstrap list is the one address source on this
// node that is not adversarial. Silently dropping it, which is what handing it
// straight to a store that requires an IP does, leaves a node with no peers
// and no message saying why.
//
// So resolve here and store the result, rather than relaxing the store: DNS is
// a name for an address, and the address is what gets dialled and gossiped.
// This is also where Bitcoin Core draws the same line — `-addnode`/`-connect`
// accept a hostname and resolve it; addrman holds addresses.
//
// An entry that is already an ip:port is returned untouched, so this costs
// nothing in the ordinary case and needs no resolver at all. Everything else
// is bounded: one deadline, at most maxBootstrapAddrs results, deduplicated.
// The error is returned rather than swallowed — a bootstrap entry that
// resolves to nothing produces the same silent, peerless node this function
// exists to prevent, so the one caller logs it.
func resolveBootstrap(ctx context.Context, addr string) ([]string, error) {
	if plausibleAddr(addr) {
		return []string{addr}, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return nil, fmt.Errorf("bootstrap address %q has no host", addr)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("bootstrap address %q resolved to nothing", addr)
	}
	return bootstrapTargets(ips, port), nil
}

// bootstrapTargets turns a resolver's answers into dial targets: deduplicated,
// and capped at maxBootstrapAddrs. Separated from the lookup so that the
// bounding can be tested without a resolver, which is the only part of this an
// answer from elsewhere controls.
func bootstrapTargets(ips []net.IPAddr, port string) []string {
	seen := make(map[string]bool, len(ips))
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if len(out) >= maxBootstrapAddrs {
			break
		}
		a := net.JoinHostPort(ip.IP.String(), port)
		if seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

// addBootstrap seeds the peer store from the --peers list.
//
// Entries that are already dial targets are added synchronously, because that
// is the ordinary case and it costs nothing. Names are resolved on their own
// goroutine: a lookup is a network round trip to a server this node does not
// control, and Start is called before the node is doing anything at all, so a
// slow or hostile resolver there stalls the whole node rather than one entry.
func (n *Node) addBootstrap() {
	var names []string
	for _, addr := range n.Bootstrap {
		if plausibleAddr(addr) {
			n.Peers.AddBootstrap(addr)
			continue
		}
		names = append(names, addr)
	}
	if len(names) == 0 {
		return
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		for _, addr := range names {
			select {
			case <-n.quit:
				return
			default:
			}
			// The deadline is cancelled by Stop as well as by time: without
			// that, wg.Wait waits out an in-flight lookup, so a slow or
			// hostile resolver adds bootstrapResolveTimeout to shutdown.
			ctx, cancel := context.WithTimeout(context.Background(), bootstrapResolveTimeout)
			stopped := make(chan struct{})
			go func() {
				select {
				case <-n.quit:
					cancel()
				case <-stopped:
				}
			}()
			resolved, err := resolveBootstrap(ctx, addr)
			close(stopped)
			cancel()
			if err != nil {
				n.log("bootstrap peer %q could not be resolved, and is being skipped: %v", addr, err)
				continue
			}
			for _, a := range resolved {
				n.Peers.AddBootstrap(a)
			}
		}
	}()
}

// Start begins dialling.
func (n *Node) Start() {
	// The last point before traffic at which an operator's MaxInbound is known
	// to be settled; register republishes it if it moves after this.
	n.publishConnectionSet()
	n.addBootstrap()
	n.wg.Add(1)
	go n.dialLoop()
	n.wg.Add(1)
	go n.syncLoop()
	n.wg.Add(1)
	go n.probationLoop()
	n.wg.Add(1)
	go n.pendingBodyLoop()
	n.wg.Add(1)
	go n.withholdLoop()
}

// pendingBodyReapInterval is how often this node checks for announced blocks
// whose bodies never arrived.
const pendingBodyReapInterval = 15 * time.Second

// pendingBodyLoop periodically scores down peers that announced a block and
// never served its body. Engine.ReapUnservedBodies does the actual
// work; this is just its clock, the same shape as probationLoop beside it.
func (n *Node) pendingBodyLoop() {
	defer n.wg.Done()
	for {
		select {
		case <-n.quit:
			return
		case <-time.After(pendingBodyReapInterval):
		}
		n.reapUnservedBodies(n.Engine.wallClock())
	}
}

// reapUnservedBodies runs one sweep and charges both tallies.
//
// The address tally is the engine's; the identity tally is this layer's,
// because the engine is handed a connection address and never a public key.
// Every other ingress path moves both — Handle adjusts the address, serve
// adjusts the key beside it — and a penalty that moved only the
// address-keyed half would be shed by reconnecting on a fresh ephemeral port,
// which is the hole identity-keyed scoring closed everywhere else.
//
// Only a peer still connected can be charged on its identity. An announcer
// that hung up before the window elapsed leaves nothing to key on, and the
// alternative — holding a public key per pending announcement so a
// ten-point penalty can outlive the connection — buys less than it costs.
// Separated from the loop so a test can drive one sweep rather than a clock.
func (n *Node) reapUnservedBodies(now time.Time) {
	for _, addr := range n.Engine.ReapUnservedBodies(now) {
		n.mu.Lock()
		c := n.conns[addr]
		n.mu.Unlock()
		if c != nil {
			n.Peers.AdjustKey(c.PeerKey, ScoreUnservedBody)
		}
	}
}

// withholdLoop re-evaluates future-dated blocks as the local clock advances.
//
// Blocks that mature are judged by the ordinary ingress path, and only those
// that are *accepted* are relayed — which is the forwarding semantics the rule
// needs. Relaying while withheld would push a timestamp onward that this node
// has not been able to validate, so the rule would hold for one hop and for
// nobody else; never relaying would make a soon-valid block's propagation
// depend on which nodes happened to receive it directly. Relay on release, and
// the block spreads at the moment the network agrees it is judgeable.
//
// The relay carries the *body*, not an announcement, and that is not a style
// choice — see relayReleased.
func (n *Node) withholdLoop() {
	defer n.wg.Done()
	// A Node built as a struct literal has a zero interval, and a zero interval
	// here is a spin loop rather than a fast one.
	interval := n.WithholdInterval
	if interval <= 0 {
		interval = time.Second
	}
	for {
		select {
		case <-n.quit:
			return
		case <-time.After(interval):
		}
		for _, rel := range n.Engine.ReleaseWithheld() {
			if rel.Verdict.Err != nil {
				n.log("released withheld block: %v", rel.Verdict.Err)
			}
			if rel.Verdict.Forward {
				n.relayReleased(rel)
			}
		}
		n.reportClockSkew()
	}
}

// skewEpisodeIdleTicks is how many withholdLoop ticks without a single
// future-dated message end an episode.
//
// An episode and not a lifetime total, because the report is rate-limited by
// doubling and a counter that only rises turns that limiter into a silencer —
// see Engine.ResetSkewEvidence for the two measurements. Sixty ticks is a
// minute at the default interval, which is two block intervals on mainnet: long
// enough that an ordinary gap in gossip does not restart the count, short
// enough that a fixed clock is forgotten before the next fault.
const skewEpisodeIdleTicks = 60

// skewMaxSilentTicks bounds how long an ongoing episode can go unmentioned.
//
// The doubling schedule alone is an adversary-settable silencer, and ending the
// episode is not enough to close that: the reset needs skewEpisodeIdleTicks
// *consecutive* quiet ticks, so one message every fifty-nine ticks keeps an
// episode open forever. Measured on the version without this floor: after a
// flood ran the count to 10^6 — a few thousand hashes a block — a genuine
// mainnet clock fault at 8 blocks per 30 s logged nothing for a simulated day —
// 23,040 blocks — and was on its way to 43 of them.
//
// So the schedule is "at each doubling, and at least this often while the
// condition continues". An hour at the default interval, which bounds both the
// silence and the noise: a permanent fault costs 24 lines a day.
const skewMaxSilentTicks = 3600

// skewReportState is what reportClockSkew remembers between ticks.
type skewReportState struct {
	// next is the count at which the next line is due. A *threshold* and not
	// the last count reported, which is the whole of the difference between a
	// rate limiter that works and one that does not — see reportClockSkew.
	next uint64
	// seen is the count at the previous tick, and idle counts the ticks since
	// it last moved. Together they decide when the episode is over.
	seen uint64
	idle int
	// sinceLine is ticks since the last line, for the floor above.
	sinceLine int
}

// reportClockSkew logs when messages are arriving dated ahead of this node's
// clock, which on an otherwise healthy node means the local clock is wrong
// — a node whose clock is slow past the future-time limit otherwise falls
// permanently behind in silence.
//
// **It reports evidence and does not return a verdict, which is deliberate and
// was arrived at the hard way.** Two earlier versions asserted whose clock was
// wrong. The first said "check this machine's clock" whenever more than one
// sender appeared, and one host on two source ports satisfied it. The second
// required a majority of this node's connected address groups, and that was
// worse in two directions at once: an attacker holding nine silent connections
// from distinct groups could push an honest majority below the threshold and
// suppress a true diagnosis outright, and `groups > 1` is unreachable by
// construction on a loopback test net, a 192.168 LAN, a docker bridge or a node
// whose peers are all inside one IPv6 /32 — which is precisely the population
// least likely to be running NTP. A rule that can be gamed in both directions
// and excludes the nodes that need it is not a diagnosis; it is a guess with a
// confident voice.
//
// The line therefore carries what is actually known — how many messages, from
// how many of this node's address groups, how far ahead, by which path, and how
// much is waiting — and names the two readings the numbers distinguish. Six
// groups out of eight is a local clock; one out of eight is that peer. The
// operator can tell those apart from the same line, and nothing an attacker
// does can make the numbers lie about themselves.
//
// **Rate-limited by crossing a doubling threshold, not by landing on one.**
// The first version of this asked whether the count was exactly a power of two
// (`count&(count-1) == 0`), which is a doubling schedule only if the count
// advances one at a time. On the drop paths it does not: seenBlocks is set by
// OnBlockAnnounce, a future-dated announcement is dropped *before* it is set,
// so OnBlock's "seen && !waiting" dedupe never fires — and node.go's serve loop
// re-broadcasts an accepted body to every peer but the sender, so those paths
// step by the peer count once per block interval while this loop ticks once a
// second. The observed values are then the multiples of the peer count, and a
// multiple of p can be a power of two only when p is itself one. Measured over
// ten simulated minutes:
//
//	drops per step   1   2   3   4   5   7  10
//	lines logged    10  10   0  10   0   0   0
//
// Three, five, seven or ten peers: thousands of blocks dropped, not one line —
// the exact silence the sensor is about, reproduced by the fix for it. A threshold
// set from the count actually observed holds the doubling property at every
// step size.
func (n *Node) reportClockSkew() {
	r := n.Engine.BeyondHorizon()
	n.skew.sinceLine++

	// End of episode: nothing future-dated for a while, and the queue has
	// drained. Both, because a standing queue *is* the condition continuing —
	// below the queue bound a slow clock loses nothing and every block is held,
	// so a backlog with no new arrivals is a node still running late, not a
	// node recovered.
	if r.Count == n.skew.seen {
		n.skew.idle++
		if n.skew.idle >= skewEpisodeIdleTicks && r.QueueDepth == 0 && r.Count > 0 {
			n.Engine.ResetSkewEvidence()
			n.skew = skewReportState{}
		}
		return
	}
	n.skew.seen = r.Count
	n.skew.idle = 0
	if r.Count == 0 {
		return
	}
	if r.Count < n.skew.next && n.skew.sinceLine < skewMaxSilentTicks {
		return
	}
	// From the count observed, not from the count wanted: a step of seven puts
	// the next line at fourteen. Saturating at the maximum rather than at half
	// of it, so the threshold can never end up *below* a count that reached it.
	if r.Count > math.MaxUint64/2 {
		n.skew.next = math.MaxUint64
	} else {
		n.skew.next = r.Count * 2
	}
	n.skew.sinceLine = 0

	// Weighed against the peers this node *chose*, which is the half of the
	// ratio nobody else can set.
	chosen, agreeing := n.outboundAgreement(r.Senders)

	// No dialled peers is "the test could not be run", not "nobody agrees", and
	// saying the second is wrong every time rather than occasionally. It is
	// reachable with no adversary at all: an empty or unreachable bootstrap
	// list, a listener-only deployment, an exhausted peer store, or simply the
	// window after boot before the first topUp. Measured on the version that
	// did not separate them: a genuine 4000 s fault with eight inbound peers
	// and nothing dialled printed "0 of them among the 0 peer(s) this node
	// dialled … the senders named are dating blocks forward".
	if chosen == 0 {
		n.log("clock check: %d message(s) dated ahead of this node's clock, from %d "+
			"address group(s)%s; worst %ds ahead (%d announcement(s) dropped, %d "+
			"block(s) queued and released late, %d dropped to a full queue, %d "+
			"dropped past the %ds horizon, %d sync pass(es) with nothing to take; "+
			"%d waiting now). This node has dialled no peers, so there is nothing "+
			"it chose to weigh this against and it cannot say whether the fault is "+
			"local: check this machine's clock (NTP), and check that this node has "+
			"outbound peers at all.",
			r.Count, r.Groups, firstGroup(r), r.MaxSkewSeconds,
			r.Announced, r.Withheld, r.QueueFull, r.BeyondHorizon,
			n.Engine.WithholdHorizonSeconds(), r.SyncPasses, r.QueueDepth)
		return
	}

	first := firstGroup(r)
	n.log("clock check: %d message(s) dated ahead of this node's clock, from %d "+
		"address group(s)%s, %d of them among the %d peer(s) this node dialled; "+
		"worst %ds ahead (%d announcement(s) dropped, %d block(s) queued and "+
		"released late, %d dropped to a full queue, %d dropped past the %ds "+
		"horizon, %d sync pass(es) with nothing to take; %d waiting now). "+
		"Dialled peers are the half of that ratio an attacker cannot open at "+
		"will: if most of them are in it, this machine's clock is the outlier "+
		"and gossip is being delayed or discarded — check this machine's clock "+
		"(NTP). If few or none are, the senders named are dating blocks forward "+
		"and the withhold path is refusing them correctly.",
		r.Count, r.Groups, first, agreeing, chosen, r.MaxSkewSeconds,
		r.Announced, r.Withheld, r.QueueFull, r.BeyondHorizon,
		n.Engine.WithholdHorizonSeconds(), r.SyncPasses, r.QueueDepth)
}

// dialledGroupsLocked is the address groups this node has dialled, for the
// Engine's cap exemption. Caller holds n.mu; the returned map is freshly built
// and handed off, so the Engine may hold it without sharing state.
//
// An address the grouping cannot parse is left out. `-peers` takes free-form
// strings, so a hostname bootstrap — `seed1.example.com:9000` — yields
// AddressGroup's invalid-address sentinel, and admitting that would exempt
// *every* unparseable sender from the cap. Measured before the guard: one such
// message on a hostname-bootstrapped node read "1 of them among the 1 peer(s)
// this node dialled", i.e. check your NTP, from a single stranger.
func (n *Node) dialledGroupsLocked() map[string]struct{} {
	_, groups := n.dialledLocked()
	return groups
}

// dialledLocked is the dialled addresses this node can weigh evidence against,
// and the address groups they fall in. Caller holds n.mu.
//
// One function decides which targets are usable, because the rule that excludes
// an unparseable address has to hold for both halves of the ratio and a copy of
// it in each is a copy that can rot: mutation found exactly that, with the guard
// in one caller pinned and the guard in the other free to be deleted.
func (n *Node) dialledLocked() (addrs, groups map[string]struct{}) {
	addrs = make(map[string]struct{}, len(n.outboundTargets))
	groups = make(map[string]struct{}, len(n.outboundTargets))
	for addr := range n.outboundTargets {
		g := AddressGroup(addr)
		if g == invalidGroup {
			continue
		}
		addrs[addr] = struct{}{}
		groups[g] = struct{}{}
	}
	return addrs, groups
}

// outboundAgreement is how many address groups this node dialled, and how many
// of them are among the senders whose messages arrived dated ahead.
//
// **The denominator is the peers this node chose, not everyone it is connected
// to, and that is the whole of what makes the ratio mean anything.** Read
// against all connections it is a number an attacker sets from both ends: he
// inflates the denominator by dialling in — eleven cheap inbound sockets took a
// measured 8-of-8 local clock fault down to 8-of-19, which reads as one bad
// peer — and he inflates the numerator by replaying a future-dated announcement
// from N address groups, which costs a measured 31 hashes to forge because
// OnBlockAnnounce checks the work a header *declares* and the announce path
// neither dedupes nor scores. Measured: ten sockets in ten /16s produced
// "10 address group(s)" on a node whose clock was exactly correct.
//
// **What this buys, stated as what it is.** Outbound targets are chosen by this
// node through SelectDiverse, from its own peer store and across address
// groups, so neither of those attacks moves the number: the inbound flood is
// simply not counted, and the forged breadth shows up as a large group count
// with no agreement, which is a visibly different shape.
//
// It is a repricing, not an impossibility, and the earlier claim that "an
// attacker cannot add himself to them by connecting" was false: Engine.OnHello
// records h.ListenAddr on every inbound handshake, so an advertised
// address does enter the store and can be selected (bounded by
// MaxPerSource against the connection that advertised it, since a claimed
// listen address is now recorded with its teller). What he must do is run
// genuinely reachable hosts in distinct address groups and win SelectDiverse
// against the honest entries. So this ratio is exactly as trustworthy as this
// node's eclipse resistance (M2-G4) and no more — which is a much higher bar
// than opening sockets, and the right bar to have tied it to.
func (n *Node) outboundAgreement(evidence []string) (chosen, agreeing int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	// The denominator counts *groups* and the numerator matches *addresses*,
	// and the asymmetry is the point. Counting the denominator by socket would
	// let one host this node dialled eight times read as eight independent
	// opinions about the time; matching the numerator by group would let one
	// stranger inside a dialled peer's /16 speak for that peer. Each half is
	// keyed on whichever unit its own attack is against.
	dialled, groups := n.dialledLocked()
	agreed := make(map[string]struct{}, len(evidence))
	for _, sender := range evidence {
		if _, ok := dialled[sender]; ok {
			agreed[AddressGroup(sender)] = struct{}{}
		}
	}
	return len(groups), len(agreed)
}

// relayReleased re-propagates a block that matured and was accepted.
//
// **As a body, and an announcement will not do.** The two are not
// interchangeable here, because of exactly where in the clock this fires. A
// block is released the first tick after `Time - FTL`, and a peer refuses it
// while `Time > peer_now + FTL` — i.e. while `peer_now < Time - FTL`. So a peer
// whose clock is behind this node's by more than the tick that released the
// block refuses it, and the two forms of refusal are not the same refusal:
//
//   - Sent as a **body**, `OnBlock` withholds it. The peer queues it and
//     releases it a second or two later, on its own clock. That is the whole
//     mechanism working exactly as designed, one hop further out.
//   - Sent as an **announcement**, `OnBlockAnnounce` refuses it and keeps
//     nothing — deliberately, since marking a future-dated id seen would dedupe
//     the re-announcement that arrives once the clock catches up. The peer is
//     left with no block and no record that one exists.
//
// Announcing would therefore have made the relay useless to precisely the peers
// it exists for: the ones whose clocks have not yet reached the release point.
// Ordinary clock skew is a second. Sending the body is what degrades into
// another withhold instead of into nothing.
//
// The body goes in the single-chunk envelope `KindBlock` carries since blocks
// began travelling as chunks, which is the same frame `Node.serve` re-broadcasts
// when it forwards an accepted block. Past one chunk there is no such frame —
// and the flood path cannot forward a multi-chunk body either, since a peer
// receiving chunk n of a transfer it is not holding refuses it — so the fallback
// is the announcement, whose round trip is the only route a block that large has
// on this path at all.
//
// **That fallback is live code, and the comment here used to say it was not.**
// It compared `BlockChunkBytes` (4 MiB) against `block_byte_limit_genesis` (2.5
// MB) and concluded "reachable only after an era re-pin". That is the wrong
// ceiling: the byte limit is not fixed at its genesis value, it scales with the
// sequential-gas target. `Params.BlockByteLimit(t)` is
// `block_byte_limit_genesis * t / seq_gas_target_genesis`, so it crosses one
// chunk at t = 4,194,304 * 1,600,000 / 2,500,000 = 2,684,354 — 1.68x the
// genesis target, and well under `seq_gas_capacity` (5,120,000), which is as
// far as `NextSeqGasTarget` may ever carry t. Driving that controller at
// sustained healthy demand reaches the crossover in 266 epochs. The crossover
// is 1.68x of t0 on every shipped network and the epoch count is the same on
// all of them, because both terms scale with seq_gas_target_genesis and it
// cancels — and because testnet and devnet carry mainnet's own sequential
// target, the absolute t does not differ either: all three carry
// t0 = 1,600,000, so 2,684,354 is the crossover on every shipped network. The
// branch therefore needs ordinary demand and no era boundary at all. Deriving
// it from t at genesis and extending the answer past those conditions gives a
// different figure and is the error to avoid: a crossover is a property of the
// regime, not of the parameter file read once.
//
// The frame is built from the bytes the queue kept, not from a re-encoding of a
// decoded block. That is not an optimisation: it is what lets the queue
// hold one representation of the block instead of two, which is what makes its
// byte bound mean what wire.md §9 rule 8 says it means.
func (n *Node) relayReleased(rel Released) {
	kind, payload, err := releaseRelay(rel, n.Engine.Chain.Params())
	if err != nil {
		// Only the multi-chunk fallback decodes, and it decodes bytes
		// ReleaseWithheld has just judged through OnBlock — which decodes them
		// too, and would not have marked the verdict Forward had they been
		// malformed. So this is unreachable rather than merely unlikely, and it
		// is logged rather than ignored precisely because a future change that
		// made it reachable would otherwise drop a block in silence.
		n.log("released block %x: cannot frame the relay: %v", rel.ID[:8], err)
		return
	}
	n.Broadcast(kind, payload, "")
}

// releaseRelay is the choice relayReleased makes, separated from the sending so
// that both of its branches can be tested. The multi-chunk one is unreachable
// at every committed parameter set and is exactly the branch that would
// reintroduce the problem the single-chunk one exists to avoid, so "no test
// covers it" and "nobody will notice when an era re-pin makes it live" are the
// same sentence.
func releaseRelay(rel Released, p *params.Params) (MessageKind, []byte, error) {
	// The body as it was delivered, not a re-encoding of a decoded block. The
	// queue holds exactly these bytes and nothing else, and they are the
	// bytes OnBlock accepted, so the relay forwards what this node judged.
	body := rel.Raw
	if ChunkCount(len(body)) != 1 {
		// The only branch that needs the block's structure, and the only reason
		// Released.Decode exists. Reachable at block_byte_capacity (8 MB against
		// a 4 MiB BlockChunkBytes) rather than only after an era re-pin, so it
		// is a live branch under the committed parameters and not dead code.
		blk, err := rel.Decode(p)
		if err != nil {
			return 0, nil, err
		}
		ann := BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
		return KindBlockAnnounce, ann.MarshalAnnounce(), nil
	}
	chunk := BlockChunk{ID: rel.ID, Chunk: 0, Total: 1, Data: body}
	return KindBlock, chunk.MarshalBlockChunk(), nil
}

// probationLoop closes reserve connections that outstayed their window.
//
// Without it the reserve is not a reserve, it is two extra permanent inbound
// slots per source — a straight widening of the eclipse bound rather than a
// separate class. The reserve's whole justification is that a connection in it
// may exist but may not persist, and this is the half that enforces "may not
// persist".
func (n *Node) probationLoop() {
	defer n.wg.Done()
	for {
		select {
		case <-n.quit:
			return
		case <-time.After(15 * time.Second):
		}
		if n.listener == nil {
			continue
		}
		for _, addr := range n.listener.ExpiredProbation() {
			n.mu.Lock()
			c := n.conns[addr]
			n.mu.Unlock()
			if c != nil {
				n.log("closing %s: reserve inbound slot outstayed its window", addr)
				c.Close()
			}
		}
	}
}

// Stop closes everything and waits for the loops to finish.
//
// This is safe to call before an operator-facing PeerStore.Save (the only
// caller today is cmd/zycordd's shutdown deferral) because wg.Wait below is
// now bounded. It used to be able to hang forever: acceptLoop ran the TLS
// handshake for every accepted connection inline, with no deadline, so one
// silent socket wedged the goroutine that held acceptLoop's own wg entry, and
// closing the listener does not interrupt a handshake already in progress on
// an already-accepted socket. The fix moved that handshake onto its own
// goroutine, off the Listener's shared accept loop and off this wg entirely
// (transport.go's Listener.acceptRaw/handshake) — so nothing left in wg can
// block on an unbounded read from a peer, and this call returns in bounded
// time whether or not a handshake happens to be in flight when it runs.
func (n *Node) Stop() {
	select {
	case <-n.quit:
		return
	default:
		close(n.quit)
	}
	if n.listener != nil {
		n.listener.Close()
	}
	n.mu.Lock()
	for _, c := range n.conns {
		c.Close()
	}
	n.mu.Unlock()
	n.wg.Wait()
}

// PeerCount returns the number of live connections.
func (n *Node) PeerCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.conns)
}

// Topology reports how this node is reachable, which is the measurement the
// networking decision's NAT reopen condition needs (§1 follow-up).
//
// A node that listens is part of the public core; one that does not is
// periphery, and can only ever make outbound connections. The share of the
// network in each is what decides whether the no-NAT-traversal choice holds.
type Topology struct {
	Listening bool
	Inbound   int
	Outbound  int
}

// Topology returns the current connection shape.
func (n *Node) Topology() Topology {
	n.mu.Lock()
	defer n.mu.Unlock()
	t := Topology{Listening: n.listener != nil}
	for addr := range n.conns {
		if n.outboundTargets[addr] {
			t.Outbound++
			continue
		}
		t.Inbound++
	}
	return t
}

// Reachability is Topology in primitives, so an observer can read it without
// depending on this package.
func (n *Node) Reachability() (listening bool, inbound, outbound int) {
	t := n.Topology()
	return t.Listening, t.Inbound, t.Outbound
}

// PeerHealth is the raw scoring state, exposed for observability only.
func (n *Node) PeerHealth() (known, banned, minScore int) {
	h := n.Peers.Health()
	return h.Known, h.Banned, h.MinScore
}

// InboundRefused reports how many inbound connections this node turned away for
// a full per-source budget. A node that does not listen refuses nothing and
// returns zero, which is a fact about it rather than a missing measurement.
func (n *Node) InboundRefused() int64 {
	if n.listener == nil {
		return 0
	}
	return n.listener.Refused()
}

// HandshakesPreempted reports how many in-flight TLS handshakes this node cut
// short to admit a newer arrival once the global handshake cap was reached.
//
// It sits beside InboundRefused for the reason that counter exists at all: a
// preempted peer sees a bare connection reset, indistinguishable from a
// network fault, and this node logs nothing. A rising count is the only way
// to tell "the network is flaky" from "something is holding this node's
// handshake budget full", and those were the same observation before.
func (n *Node) HandshakesPreempted() int64 {
	if n.listener == nil {
		return 0
	}
	return n.listener.Preempted()
}

func (n *Node) acceptLoop() {
	defer n.wg.Done()
	for {
		conn, err := n.listener.Accept()
		if err != nil {
			select {
			case <-n.quit:
				return
			default:
			}
			return
		}
		// Capacity, registration and cleanup all happen inside serve, behind
		// one guaranteed release of the inbound slot Accept charged this
		// connection against — see serve's own comment.
		n.wg.Add(1)
		go n.serve(conn, false)
	}
}

func (n *Node) dialLoop() {
	defer n.wg.Done()
	for {
		n.topUp()
		// Discovery rides the dial loop rather than owning a goroutine
		// because it asks about exactly the resource this loop consumes, and
		// because the peers it may ask are the ones this loop just chose.
		// Its own interval gates it; see askForPeers.
		n.askForPeers()
		// Jitter, so a restarted network does not synchronise its dials into a
		// thundering herd.
		wait := n.DialInterval + time.Duration(n.rng.Int63n(int64(n.DialInterval/2+1)))
		select {
		case <-n.quit:
			return
		case <-time.After(wait):
		}
	}
}

// dialTargets is the choice topUp makes, separated from the dialling so that
// it can be tested across rounds without a socket.
//
// The separation is not cosmetic. What this returns is the whole of the
// address-diversity defence, and the bug that made both of its bounds
// decorative lived here, in the arguments — passing the held connections only
// as an *exclusion*, which removes them from the candidate set before either
// budget is counted, so every round began with both budgets full again. A test
// that drives the selector directly cannot see that; the mistake is only
// visible in what the caller hands it, round after round.
func (n *Node) dialTargets() []string {
	n.mu.Lock()
	connected := make(map[string]bool, len(n.conns))
	for addr := range n.conns {
		connected[addr] = true
	}
	// A self-address is excluded, not merely ranked low. It spends no
	// budget here (exclusion is applied before the diversity and per-source
	// counters are built), so removing it costs a real peer nothing.
	//
	// Expiry is applied on read, which is also where the map is pruned: the
	// dial loop is the only reader, it runs every DialInterval, and an entry
	// nobody will consult again should not be kept alive by the absence of a
	// sweeper.
	now := time.Now()
	for addr, until := range n.selfAddrs {
		if now.After(until) {
			delete(n.selfAddrs, addr)
			continue
		}
		connected[addr] = true
	}
	// The bound address, compared before any socket is opened. This is the
	// cheap half of the guard and it only catches the address this node
	// actually bound — a wildcard bind renders it "[::]:port", which matches
	// no candidate. Everything it misses is caught by ErrSelfConnection on
	// the key, which is why that one and not this one is the guard of record.
	if own := n.ListenAddr(); own != "" {
		connected[own] = true
	}
	held := make([]string, 0, len(n.outboundTargets))
	for addr := range n.outboundTargets {
		held = append(held, addr)
	}
	need := n.MaxOutbound - len(n.outboundTargets)
	n.mu.Unlock()
	if need <= 0 {
		return nil
	}
	// held, not just connected: the diversity and per-source budgets are
	// counted per call, so a round that only excluded the peers it already had
	// would start both budgets at zero every time and hand the same teller —
	// or the same /16 — another allowance every DialInterval. See
	// SelectDialTargets.
	return n.Peers.SelectDialTargets(need, connected, held)
}

// DialTimeout bounds one outbound dial: the TCP connect and the TLS handshake
// behind it (tls.DialWithDialer carries the dialer's timeout into the
// handshake). It was an unnamed literal inside topUp until the eclipse pass, where the
// question "what does one unreachable target cost a dial round" had to be
// answerable to say whether the round needed to be concurrent.
const DialTimeout = 5 * time.Second

// dial is Identity.Dial, indirected so that a dial round can be driven without
// sockets.
//
// Identity is a concrete type with no interface behind it, so a round's
// *scheduling* — which is what that pass changed — is otherwise only observable
// against real listeners, and only for targets in distinct /16s, which loopback
// cannot supply. Production never sets the field; a nil one is the real dialler,
// so the default path is the one that ships.
func (n *Node) dial(addr string, timeout time.Duration) (*Conn, error) {
	if n.dialFn != nil {
		return n.dialFn(addr, timeout)
	}
	return n.Identity.Dial(addr, timeout)
}

// topUp dials one round's worth of targets.
//
// **The dials run concurrently; everything decided about them runs serially
// afterwards.** The round used to be a serial loop, and a serial loop makes a
// round cost the sum of its dial timeouts rather than the longest one: eight
// unreachable addresses at the DialTimeout above is a forty-second round during
// which this node dials nobody else, and an attacker's invented addresses are
// unreachable by construction. That is the half of the eclipse the tie-break
// alone does not reach — arrival order decides *who* is chosen, and this decides how
// long a bad choice costs — and it is why the flood measured 0 honest outbound
// connections over ten simulated rounds: the rounds were not where the time
// went.
//
// Only Identity.Dial moves off this goroutine. The bookkeeping that follows a
// dial — MarkConnected/MarkFailed, the outbound reservation, and the serve
// goroutine that is obliged to give it back — is still done here, in the order
// the targets were chosen, so no lock ordering, no reservation accounting and
// no published-set ordering changes with this. The round waits for its own
// goroutines before returning, so a dial can never outlive the dial loop that
// started it (Stop closes quit and then waits on n.wg, which tracks dialLoop).
func (n *Node) topUp() {
	targets := n.dialTargets()
	if len(targets) == 0 {
		return
	}
	type dialled struct {
		addr string
		conn *Conn
		err  error
	}
	results := make([]dialled, 0, len(targets))
	var wg gosync.WaitGroup
	var mu gosync.Mutex
	for _, addr := range targets {
		select {
		case <-n.quit:
			// Stop asked; do not start what has not started. The dials
			// already in flight are still waited for below.
			continue
		default:
		}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			conn, err := n.dial(addr, DialTimeout)
			mu.Lock()
			results = append(results, dialled{addr: addr, conn: conn, err: err})
			mu.Unlock()
		}(addr)
	}
	wg.Wait()
	// Deterministic order, independent of which dial finished first: the
	// reservations and the peer-store writes below are the node's own state,
	// and letting the network decide the order they happen in is the shape of
	// bug this file has paid for before.
	sort.Slice(results, func(i, j int) bool { return results[i].addr < results[j].addr })
	for _, r := range results {
		addr, conn, err := r.addr, r.conn, r.err
		if err != nil {
			// A dial that reached this node's own identity is still a dial
			// that failed, and is scored as one — but it also says something
			// about the address that a failure count does not, so the
			// address is held out of the candidate set for a while rather
			// than left to be re-chosen at rank 0 whenever nothing better is
			// known. For a while, not forever: see Node.selfAddrs.
			if errors.Is(err, ErrSelfConnection) {
				n.retireSelfAddr(addr)
				n.log("dial target %q reached this node's own identity, and is held out of the dial set for %s", addr, SelfAddrExclusion)
			}
			n.Peers.MarkFailed(addr)
			continue
		}
		n.Peers.MarkConnected(addr)
		n.reserveOutboundTarget(addr)
		// Nothing may return between the reservation above and the goroutine
		// that is obliged to give it back.
		n.wg.Add(1)
		go n.serve(conn, true)
	}
}

// reserveOutboundTarget claims one unit of this node's dial budget for addr,
// and is the only place outboundTargets is written to.
//
// Its twin is retire. They are a pair in the same sense that
// Listener.Accept's slot charge and Listener.Release are, and for the same
// reason: the reservation is taken before the connection is admitted anywhere,
// so the giving back cannot be attached to the admission.
func (n *Node) reserveOutboundTarget(addr string) {
	n.mu.Lock()
	if n.outboundTargets == nil {
		n.outboundTargets = map[string]bool{}
	}
	n.outboundTargets[addr] = true
	// Pushed to the Engine on every change, because the cap it feeds is
	// applied when evidence is *recorded*, not when it is reported.
	dialled := n.dialledGroupsLocked()
	n.mu.Unlock()
	n.Engine.SetDialledGroups(dialled)
}

// retire gives back everything one connection holds. It is the release path,
// and the only place production code deletes from outboundTargets — but it is
// no longer the only place production code deletes from conns: register removes
// a victim from that map when it evicts at capacity, and nowhere else does. The
// two are distinguished by the evicted flag set at the eviction, without which
// they would race over one address; the last paragraphs below are about that
// window, and the ones before them about this one.
//
// One function rather than two, and one critical section rather than two, and
// both of those are load-bearing.
//
// *One function*, because the reservation and the admission have different
// lifetimes: topUp claims outboundTargets before serve is even launched, so a
// release attached to the admission is skipped by every refusal the admission
// gate can make — which is how a refused dial used to leak its reservation
// permanently. serve installs this before that gate, so a refusal added later
// cannot skip it, exactly as the inbound slot release is installed before it
// for the same reason.
//
// *One critical section*, because between the two deletions the address is
// reserved and unconnected, and that pair is a state the dial loop must never
// see. dialTargets excludes n.conns but only *charges* outboundTargets against
// the diversity budgets — PeerStore.selectLocked's fallback pass admits up to
// MaxFallbackPerGroup per group — so an address in that window can be handed
// straight back to topUp and re-dialled, and the release still to come would
// then drop the new connection's live reservation. That is the same accounting
// defect with the sign flipped: a dial budget larger than the connections this
// node holds.
//
// admitted says whether register took this connection; outbound says whether
// topUp reserved for it. They are separate answers — a refused outbound dial is
// the whole point of this function — so neither implies the other. A connection
// register already evicted skips both, and that is the one thing inbound
// eviction adds here. An evicted connection is out of the table the moment the
// arrival takes its place, and its own serve goroutine reaches this function
// some time later — after the far end notices the reset — by which point
// another connection may legitimately hold the same address: an inbound peer
// reconnecting from the same ephemeral port, which is exactly the churn an
// eviction provokes. Deleting on address alone would then remove the live entry
// and forget the live peer's tip, and the delete-then-forget pair is precisely
// what makes that silent rather than loud.
//
// The check is a flag on the Conn rather than a pointer comparison against the
// table, because unregister is called from tests with a fresh Conn value
// carrying only the address — see its comment — and a pointer comparison would
// turn every one of those into a leaked entry.
func (n *Node) retire(c *Conn, outbound, admitted bool) {
	n.mu.Lock()
	forget := false
	if admitted {
		_, stillHeld := n.conns[c.Addr]
		if c.evicted {
			forget = !stillHeld
		} else {
			delete(n.conns, c.Addr)
			forget = true
		}
	}
	if outbound {
		delete(n.outboundTargets, c.Addr)
	}
	dialled := n.dialledGroupsLocked()
	n.mu.Unlock()
	n.Engine.SetDialledGroups(dialled)
	if forget {
		n.Engine.forgetPeer(c.Addr)
	}
}

// DefaultGetPeersInterval is how often a node asks for addresses.
//
// Five minutes is chosen from the cost of the answer rather than from the
// value of it. The reply is rebuilt from the whole peer store per request and
// was measured at ~5.7ms and ~425KB of garbage at a full store, superlinear
// in store size (still open). The asker is not who pays, so the rate is
// sized against the server: one ask per node per interval is a network mean
// of one served request per node per interval, but a node is asked by the
// peers that dialled *it*, so the worst honest payer is a node with a
// saturated inbound set — MaxInbound = 32 — at 32 x 5.7ms per 300s, under
// 0.07% of a core. Honest discovery therefore cannot be what makes that cost
// bind even for the node that pays most, and it does not have to be fixed first. Any
// interval short enough for that to stop being true would be an interval at
// which this node was the amplifier.
//
// The value side needs no more than this: one answer carries up to
// MaxPeersPerResponse addresses, so a single reply is already a larger
// address set than an Era-0 bootstrap list, and the first ask is due
// immediately (Node.nextGetPeers).
const DefaultGetPeersInterval = 5 * time.Minute

// askForPeers sends one get-peers, to one peer, at most once per
// GetPeersInterval.
//
// This is the whole of the send side, and every narrowing in it is load-bearing.
//
// **One peer, not all of them.** Broadcasting would make this node's request
// rate scale with its connection count, which is the shape that turns a
// discovery timer into a network-wide load multiplier, and it buys nothing:
// one reply already carries up to MaxPeersPerResponse addresses.
//
// **An outbound peer, never an inbound one.** An outbound connection is one
// this node chose, from an address that survived SelectDialTargets' diversity
// and per-source bounds. An inbound connection is one the *peer* chose, so
// asking it lets an attacker that merely connects here nominate itself as
// this node's address source — the same reasoning by which an inbound peer is
// not a sync candidate. It costs nothing honest: an inbound peer that
// wants to teach this node addresses can still volunteer a peers frame, which
// is the only way any address has reached this node until now.
//
// **Nothing is armed when there is nobody to ask.** The interval is advanced
// only when a frame is actually sent, so a node with no outbound connections
// does not spend its asks on an empty peer set and then wait out the interval
// once it finally has one.
//
// **Jitter, re-drawn per ask.** A fixed period makes the send times of every
// connection this node holds one recognisable phase, which is a correlator
// across connections that peer-key rotation (decisions/networking.md §10) is
// otherwise meant to deny. It does not hide that this implementation asks at
// all; nothing here tries to, and see the decision doc for why that residual
// is accepted rather than argued away.
//
// **A uniform draw, not a fixed position.** The list is sorted so a seeded
// soak run stays reproducible, which is the property Node.rng exists for —
// but the sort is not the choice. Picking a fixed position out of it, the
// first candidate say, would make whichever peer holds that position this
// node's standing and only address source, across restarts, collapsing the
// 1/MaxOutbound bound on what one hostile outbound slot can supply to 1/1 for
// the price of an address that sorts low. Rotating is what keeps that a bound.
func (n *Node) askForPeers() {
	if n.GetPeersInterval <= 0 {
		return
	}
	now := time.Now()
	n.mu.Lock()
	if now.Before(n.nextGetPeers) {
		n.mu.Unlock()
		return
	}
	candidates := make([]string, 0, len(n.outboundTargets))
	for addr := range n.outboundTargets {
		if n.conns[addr] != nil {
			candidates = append(candidates, addr)
		}
	}
	if len(candidates) == 0 {
		n.mu.Unlock()
		return
	}
	sort.Strings(candidates)
	target := candidates[n.rng.Intn(len(candidates))]
	c := n.conns[target]
	n.nextGetPeers = now.Add(n.GetPeersInterval +
		time.Duration(n.rng.Int63n(int64(n.GetPeersInterval/2+1))))
	n.mu.Unlock()

	// get-peers carries an empty payload (wire.md §7). SendDeadline, not
	// Send: a reply or a Broadcast may be writing to this same connection.
	if err := c.SendDeadline(KindGetPeers, nil, time.Now().Add(writeTimeout)); err != nil {
		n.log("get-peers to %s failed: %v", target, err)
	}
}

// How long a self-verdict holds an address out of the dial set, and how many
// such addresses are remembered at once.
//
// Both are bounds on the same thing: how much an on-path attacker gains by
// arranging that this node authenticates to itself at an address that is not
// its own. Neither number is a guarantee, and both are policy rather than
// consensus — they belong on the tunable half of
// docs/decisions/testnet-measurements.md with the reserve and probation
// constants.
//
// Ten minutes, because the cost of being wrong is not symmetric. Forgetting
// too early costs one dial attempt per self-address per window; against a
// DialInterval measured in seconds and eight outbound slots, that is a
// fraction of a percent of this node's dialling. Forgetting too late is an
// honest peer this node refuses to call, for no reason it can observe or an
// operator can diagnose. So the window is sized much longer than the churn it
// exists to suppress and much shorter than an outage anyone would notice.
//
// The cap exists because the entries are attacker-inducible: an attacker on
// the path to many addresses can arrange many self-verdicts, and a map with
// only a time bound still grows with the attack's breadth. Sixty-four is far
// above the number of addresses that genuinely reach one process — that set
// is interfaces and NAT mappings, not peers — so a legitimate entry is never
// the one evicted in practice.
const (
	SelfAddrExclusion = 10 * time.Minute
	maxSelfAddrs      = 64
)

// retireSelfAddr holds an address out of the dial set until SelfAddrExclusion
// has passed.
//
// At the cap it drops the entry closest to expiring rather than refusing the
// new one. Refusing would make the map's *first* sixty-four entries the
// long-lived ones, which hands an attacker the durable outcome the expiry
// exists to deny: fill it early, and every later self-address — including
// this node's real ones — is never recorded at all.
func (n *Node) retireSelfAddr(addr string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.selfAddrs == nil {
		n.selfAddrs = map[string]time.Time{}
	}
	if _, known := n.selfAddrs[addr]; !known && len(n.selfAddrs) >= maxSelfAddrs {
		var soonestAddr string
		var soonest time.Time
		for a, until := range n.selfAddrs {
			if soonestAddr == "" || until.Before(soonest) {
				soonestAddr, soonest = a, until
			}
		}
		delete(n.selfAddrs, soonestAddr)
	}
	n.selfAddrs[addr] = time.Now().Add(SelfAddrExclusion)
}

// register admits one connection to the served set, or refuses it.
//
// The inbound capacity gate is here, in the same critical section as the
// insert it guards, and that is why the function takes `outbound` rather than
// letting serve decide first. It used to be a separate read in serve — lock,
// compare len(n.conns) against the cap, unlock, then call a register that
// only checked for a duplicate address — and a check-then-act across a
// released lock does not bound anything: every serve goroutine inside the
// window between the two sections observes the same under-capacity count, and
// every one of them then inserts. acceptLoop spawns one such goroutine per
// accepted connection with nothing standing between them, so the overshoot is
// the arrival burst's width, and it is durable rather than transient: an
// admitted connection keeps its entry until it disconnects.
//
// That is a memory bound and not only a socket bound. MaxReassemblyBytes bounds
// *buffered* reassembly bytes; the connection set is the multiplier on
// everything the reassembly path holds outside that counter — per-peer transfer
// slots, and the body a completed transfer hands to OnBlock while the budget
// has already been repaid. A cap the connection set can walk through multiplies
// all of it by a number nobody chose.
//
// The gate stays inbound-only, exactly as it was. Refusing an outbound dial
// because inbound had filled the table would let a flood of inbound
// connections suppress this node's own dialling, which is the eclipse shape
// address diversity exists to prevent; outbound is bounded instead by topUp, which is
// sequential in dialLoop and dials only up to MaxOutbound - len(outboundTargets).
//
// This moves no check across anything §10.1 of docs/spec/wire.md orders: the
// gate reads and admits at exactly the point in serve it already did, on a
// connection the listener has already authenticated, and no signature or
// proof-of-work evaluation sits between the old position and this one.
//
// The third gate is the per-identity one, MaxConnsPerIdentity: see its comment
// for why the keyspace is the Ed25519 identity and not the address.
func (n *Node) register(c *Conn, outbound bool) bool {
	// Published from register and not only from NewNode, because MaxInbound and
	// MaxOutbound are exported fields an operator sets after construction. The
	// engine's node-wide key-epoch ceiling is derived from this set, so reading
	// it here — in the function whose gate defines the set — is what keeps the
	// two from drifting apart. See Engine.unheldKeyEpochCeiling.
	defer n.publishConnectionSet()
	// The evicted connection is closed after the lock is released and before
	// the set is published: closing a socket under n.mu would put a syscall
	// inside the critical section every accept contends on, and publishing
	// before the close would announce a set this node has not finished
	// changing. Go runs deferred calls last-registered-first, so the order
	// here is Unlock, then Close, then publish.
	var victim *Conn
	defer func() {
		if victim != nil {
			victim.Close()
		}
	}()
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, dup := n.conns[c.Addr]; dup {
		return false
	}
	// The per-identity cap, in the same critical section as the two beside it
	// and for the same reason: a count taken outside the lock that guards the
	// insert bounds nothing at all, and the arrival burst's width is exactly
	// how far past the cap a split section would let one identity get.
	//
	// It is checked *before* the capacity gate below, so that a connection this
	// gate is going to refuse anyway never causes an eviction: an identity at
	// its cap must not be able to spend somebody else's slot on the way to
	// being turned away.
	//
	// A nil or empty PeerKey is never refused here. Every Conn the transport
	// builds carries the key TLS authenticated, so an unkeyed Conn is a test
	// fixture or a future non-TLS leg; refusing on an absent key would collapse
	// every such connection into one identity and cap the whole table at
	// MaxConnsPerIdentity.
	if len(c.PeerKey) > 0 {
		same := 0
		for _, held := range n.conns {
			if bytes.Equal(held.PeerKey, c.PeerKey) {
				same++
			}
		}
		if same >= MaxConnsPerIdentity {
			return false
		}
	}
	if !outbound && len(n.conns) >= n.MaxInbound+n.MaxOutbound {
		// At capacity, evict rather than refuse — but only when the table
		// holds a connection from a more concentrated address group than this
		// arrival's would be. See inboundVictimLocked.
		victim = n.inboundVictimLocked(c)
		if victim == nil {
			return false
		}
		delete(n.conns, victim.Addr)
		victim.evicted = true
		n.evicted++
	}
	c.outbound = outbound
	c.admittedAt = time.Now()
	n.conns[c.Addr] = c
	return true
}

// inboundVictimLocked picks the admitted inbound connection to give up so a
// new inbound arrival can be admitted, or nil to refuse the arrival instead.
// Callers hold n.mu.
//
// **Why the table needs this at all.** The handshake budget has had it since
// the inbound slot leak was closed — Listener.victimLocked takes the oldest
// handshake from whichever address group holds the most in flight — and the
// admitted table, one gate later, had nothing: register refused at
// MaxInbound+MaxOutbound and never evicted. So the table was
// first-come-first-served and permanent, and a connection costs nothing to
// hold: a 9-byte count-0 `headers` or `peers` frame every under-60s keeps the
// read deadline alive and is scored nothing. Fourteen addresses across distinct
// /16s at three connections each is 42 against a table of 40, after which no
// honest peer can ever open an inbound connection to this node — the half of
// the eclipse that closes the door behind the other three. Bitcoin Core's
// AttemptToEvictConnection exists for exactly this, and this is that policy at
// the size this table is.
//
// **Group share is the key, for the reason networking.md §5 already settled
// for the accept path: it is the one signal that does not invert.** Age alone
// says "evict the slowest", and the slowest peer is a distant honest one, not
// a local attacker who controls its own connection lifetime. Score alone
// inverts too: an attacker that behaves is indistinguishable from a peer that
// is merely quiet. Holding the table requires *breadth*, and breadth is the
// thing an attacker has to buy.
//
// **What is protected.**
//
//   - Outbound connections are never candidates. They are the connections this
//     node chose, from addresses that survived SelectDialTargets' diversity and
//     source bounds; letting an inbound arrival evict one would hand an
//     attacker that merely connects here the power to unpick this node's own
//     dialling, which is the eclipse this whole file is about.
//   - A connection alone in its address group is never evicted while any
//     candidate from a larger group exists — that is the diverse subset, and it
//     is what keeps the singleton honest peer beside a flood.
//   - Among candidates, one that has recently delivered something worth
//     scoring outranks one that has not: never-useful goes first, then least
//     recently useful. That is the recently-useful subset, and it is a
//     preference rather than an exemption, because a peer's usefulness is a
//     thing an attacker can also supply, just not for free.
//   - The youngest connection goes before an older one of equal standing. An
//     attacker that churns keeps its connections newer than an honest peer's,
//     so youngest-first is what stops churn from being an advantage. This is
//     the opposite sign to victimLocked's, deliberately: there the entries are
//     *pending* handshakes, where old means stalled.
//
// **The arrival does not get to concentrate the table.** A victim is returned
// only if its group holds strictly more connections than the arrival's group
// would after admission. So the attacker's fourth connection from a group that
// already holds three cannot evict anything — not an honest singleton, and not
// one of its own — while an honest peer arriving as its group's only connection
// evicts from any group holding two or more. When every group holds exactly
// one, nothing is evicted and the arrival is refused exactly as it was before
// this existed: a table full of diverse peers is the state the policy is
// protecting, not one it should churn.
func (n *Node) inboundVictimLocked(arriving *Conn) *Conn {
	share := make(map[string]int, len(n.conns))
	for _, held := range n.conns {
		if held.outbound {
			continue
		}
		share[AddressGroup(held.Addr)]++
	}
	mine := share[AddressGroup(arriving.Addr)] + 1
	var victim *Conn
	var bestShare int
	for _, held := range n.conns {
		if held.outbound {
			continue
		}
		s := share[AddressGroup(held.Addr)]
		if s <= mine {
			continue
		}
		if victim == nil || s > bestShare || (s == bestShare && worseInboundConn(held, victim)) {
			victim, bestShare = held, s
		}
	}
	return victim
}

// worseInboundConn reports whether a should be given up before b, for two
// inbound connections whose address groups are equally concentrated. See
// inboundVictimLocked for what each key is protecting.
func worseInboundConn(a, b *Conn) bool {
	au, bu := a.lastUseful.Load(), b.lastUseful.Load()
	if au != bu {
		return au < bu
	}
	if !a.admittedAt.Equal(b.admittedAt) {
		return a.admittedAt.After(b.admittedAt)
	}
	// Two connections this node cannot otherwise separate. Decided on the
	// address so the answer does not depend on Go's map iteration order, which
	// would make the whole policy unobservable from a test.
	return a.Addr > b.Addr
}

// Evicted reports how many admitted inbound connections this node gave up to
// admit a newer arrival once the connection table was full.
//
// Nothing reports it yet; read it the way Listener.Preempted is read: the peer
// on the other end sees an ordinary connection reset and this node logs
// nothing. A rising count means the table is full and its occupancy is
// concentrated — either legitimate load has outgrown MaxInbound, or something
// is holding slots; a flat one means the table has never been full with an
// unevenly distributed set.
func (n *Node) Evicted() int64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.evicted
}

// MaxConnsPerIdentity bounds how many connections one authenticated Ed25519
// identity may hold in the served set at once.
//
// Every per-identity budget this node keeps — reply bytes, key epochs, score —
// is keyed on the identity rather than on the connection, so the connection set
// is the multiplier on each of them: an identity holding the whole table costs
// as many transfer slots, reassembly buffers and reply pipelines as there are
// connections, for the price of one keypair and as many ephemeral ports. The
// address-keyed bounds do not reach this. Listener.perSource caps one address
// group at three, and MaxInbound+MaxOutbound caps the table; between them a
// single identity dialling from a handful of groups can still hold most of it,
// which is the multiplier this constant collapses from the table's size to a
// constant.
//
// **Not one.** Refusing the second connection outright is devp2p's
// DiscAlreadyConnected (reason 0x05), and it forces a simultaneous-open
// tie-break: two honest peers that dial each other at the same moment each
// refuse the other's inbound leg and can drop both, which is connection
// flapping bought with extra code. Admitting the honest crossing pair — this
// node's outbound meeting the peer's inbound — costs no tie-break machinery at
// all and still collapses the multiplier.
//
// **Where the four come from, and why not two.** An earlier decision
// pinned two, on the premise that the honest concurrent set between a pair of
// peers *is* the crossing pair. In this tree it is not, and enforcing two froze
// sync; four is the ratified re-pin and two is withdrawn:
//
//   - 2 — the steady-state gossip pair above.
//   - +1 — the dedicated connection Node.SyncFrom opens for every sync attempt
//     (wire.md §12: no request ids and no state machine, paid for with a socket
//     per attempt). It arrives at the peer's register as a *third* leg carrying
//     the same authenticated key, and refusing it is not a refused dial:
//     syncOnce re-routes to syncOverGossip only on ErrUndialable, and a close
//     after a completed TLS handshake is not that, so the attempt is lost
//     outright. A node behind the tip is then refused by every candidate it
//     holds a pair with — the permanent freeze a node that never syncs from an
//     inbound peer suffers, entered through a new door.
//     TestSyncSurvivesAPeerThatAlreadyHoldsACrossingPair is the pin.
//   - +1 — slack, so the bound is not exactly the honest maximum. A peer's
//     store can honestly hold two addresses for this node (a seed name and a
//     gossiped address) and dial both; and a sync leg's entry is released by
//     its own serve goroutine noticing the close, not by the peer's Close
//     returning, so a replacement dial can briefly overlap the leg it replaces.
//     A cap sitting exactly on the honest maximum turns either into a refusal.
//     The cost of a wrong refusal here is a sync freeze; the cost of one extra
//     slot is one connection.
//
// Four still bounds every per-identity budget by a constant: against a table of
// MaxInbound + 2*MaxOutbound = 48 it is a twelvefold collapse, and the property
// the cap exists for — that one keypair cannot multiply itself across the table
// — is a property of the bound being constant, not of its being two. The
// node-wide Engine.replyByteCeiling still stands over the whole layer besides.
//
// Returning to two needs the sync leg to stop being a connection of its own:
// either sync is multiplexed onto the gossip connection (request ids and a state
// machine, the thing wire.md §12 declined), or the wire lets admission tell a
// sync leg from a gossip leg so the cap can be split. register runs before any
// frame is read and nothing in the TLS handshake distinguishes the two, so both
// are protocol changes — not something to take for a policy constant.
//
// Refusal carries no score penalty. A crossing dial is honest, and a refusal
// here is admission working rather than misbehaviour, counted the way
// Listener.refused counts a full budget. The cap applies to inbound and
// outbound legs alike: an identity already granted its slots is at its bound
// however the next one arrives.
//
// The number is policy, not protocol — the same status as MaxIdentities and
// Listener.perSource, and like them it belongs on the tunable half of
// docs/decisions/testnet-measurements.md. It is not consensus: a peer that
// disagrees is refused a connection, not a block. No operator-facing knob is
// exposed for it yet; that is deferred until there is traffic to size it
// against, and the value is revisited there against the sustained-bandwidth
// measurement along with the rest of the per-identity budgets.
const MaxConnsPerIdentity = 4

// publishConnectionSet hands the Engine the connection-set size the key-epoch
// ceiling is derived from.
//
// Called from NewNode, from Start and from register, which between them cover
// every way a configured value can arrive: the defaults, an operator setting
// the fields before starting, and a change made after. It is idempotent and
// costs one mutex acquisition, which against the rate connections are opened at
// is not a cost worth keying on.
func (n *Node) publishConnectionSet() {
	// A Node is a struct with exported fields and nothing requires an Engine;
	// the package's own admission test builds the smallest Node register reads
	// and gives it none. Separated by that shape rather than unreachable.
	if n.Engine == nil {
		return
	}
	n.mu.Lock()
	maxInbound, maxOutbound := n.MaxInbound, n.MaxOutbound
	n.mu.Unlock()
	n.Engine.SetConnectionSet(maxInbound, maxOutbound)
}

// unregister takes an admitted connection out of the served set. It is retire
// with the admitted answer already known, kept for the tests that drive a
// disconnect directly.
func (n *Node) unregister(c *Conn) { n.retire(c, false, true) }

// serve runs one peer's message loop.
//
// The inbound slot Listener.Accept charged this connection against is
// released exactly once, in the defer below, on every exit path this
// function has: full capacity, a lost register race, a banned identity, a
// protocol violation, or an ordinary disconnect. It used to be released only
// by unregister, and two paths returned before unregister's own defer was
// ever installed — the capacity check (formerly in acceptLoop, before serve
// was even called) and a lost register race (below, before the line that
// installs unregister's defer). Both leaked the slot for the rest of the
// process's life, eventually refusing that whole address group forever.
//
// Installing the release here, first, rather than at each rejection site, is
// the structural version of that fix: a rejection path added later cannot
// repeat the mistake, because it has to return through this defer to leave
// the function at all. Release takes conn.slotToken rather than conn.Addr —
// two accepted connections can share an observed address, and a token minted
// once per Accept is what keeps their releases independent (see Listener's
// classOf comment). Release(0) — every outbound Conn's slotToken, and any
// inbound Conn this listener never charged — is always a safe no-op, so
// calling it unconditionally on every inbound exit is safe too.
func (n *Node) serve(conn *Conn, outbound bool) {
	defer n.wg.Done()
	defer conn.Close()
	if !outbound {
		defer n.listener.Release(conn.slotToken)
	}

	// The same treatment for the dial-budget reservation topUp claimed before
	// this goroutine started: installed before the gate below, so no refusal
	// that gate can make skips it. admitted is what this defer does not
	// know yet, and it is why the teardown is one function rather than a
	// release here and an unregister further down — see retire.
	//
	// Reading admitted here rather than passing it is not a race: it is a local
	// of this goroutine, written on the line after the gate and read by this
	// goroutine's own defer.
	admitted := false
	defer func() { n.retire(conn, outbound, admitted) }()

	// Table capacity, duplicate address and the per-identity cap are one atomic
	// decision inside register; see its comment for why they cannot be three.
	if !n.register(conn, outbound) {
		return
	}
	admitted = true

	// A banned identity is refused before it is given anything to say,
	// including the handshake reply — otherwise reconnecting on a fresh
	// ephemeral port buys a banned peer a brand new invalid-message budget
	// for the cost of one TLS handshake. Conn.PeerKey is always
	// populated by this point: the TLS handshake that produced this Conn
	// already extracted and verified it, for both inbound and outbound
	// connections.
	if n.Peers.BannedKey(conn.PeerKey) {
		n.log("refusing %s: peer identity is banned", conn.Addr)
		return
	}

	// The handshake first, always. Until the network ids match, nothing this
	// peer says is worth parsing (M2-G6).
	if err := conn.SendDeadline(KindHello, n.Engine.Hello().MarshalHello(),
		time.Now().Add(writeTimeout)); err != nil {
		return
	}

	for {
		select {
		case <-n.quit:
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		kind, payload, err := conn.Receive()
		if err != nil {
			return
		}

		// A frame that answers a sync request this node made on *this*
		// connection belongs to that request, not to the gossip handler.
		// deliverSyncResponse claims a frame only while an attempt is
		// actually waiting for that exact kind and, for a body chunk, for
		// that exact block and chunk index — so an unsolicited frame, and a
		// gossip body chunk for any other block, still reach Engine.Handle
		// and are scored exactly as before.
		if n.deliverSyncResponse(conn.Addr, kind, payload) {
			continue
		}

		// The authenticated identity travels with the message, not only the
		// socket it arrived on. The engine keys the served-reply byte budget
		// on it; everything else about this call is unchanged, and the
		// address-keyed Adjust inside Handle still moves exactly as before.
		v := n.Engine.HandleFrom(conn.Addr, conn.PeerKey, kind, payload)
		// Engine.Handle already scored the connection address (Adjust, in
		// engine.go). This scores the peer's authenticated identity as well
		// — a second, independent tally a reconnect on a new source port
		// cannot reset — checked below alongside the address ban.
		if v.Score != 0 {
			n.Peers.AdjustKey(conn.PeerKey, v.Score)
		}
		// The usefulness stamp the inbound eviction policy ranks on.
		//
		// It is the *scored* verdict and not a frame or byte count on purpose:
		// the connections that policy exists to reach are held open by a 9-byte
		// count-0 frame that returns CostFree, so a traffic counter would rank
		// a squatter as this node's busiest peer. A positive score is
		// wire.md §10's "new and valid", which is the one thing a slot-holder
		// cannot supply for nothing.
		if v.Score > 0 {
			conn.lastUseful.Store(time.Now().UnixNano())
		}
		// A second, independent log predicate — keyed on the error's locality,
		// not on the peer's culpability: a gossip-path local refusal would otherwise
		// be logged nowhere at all.
		//
		// A refusal caused by this node's own fault (a failed commit, a record
		// this store cannot decode, a reorg that could not be undone) comes back
		// as Verdict{Cost: CostFree, Score: 0, Err: err}: correct, because an
		// innocent peer must not pay for our disk. But the only log gate on this
		// path used to be the ScoreProtocolViolation drop below, which is keyed
		// on culpability — so the one class of error that is definitely this
		// node's problem was the one class guaranteed to be silent, whatever it
		// was. Keying this on the whole chain.ErrLocal class rather than on any
		// single error is the point: a local fault added later inherits the log
		// instead of inheriting the silence.
		//
		// It logs and continues. No disconnect, no score adjustment, no change
		// to the gate below, which keeps its dual role (log + drop) for culpable
		// peers exactly as before. Not rate limited on purpose: a node whose
		// disk is failing under gossip load should be loud, and in a healthy
		// node the frequency of local faults is not peer-controllable. This also
		// restores symmetry with the node's other door — syncLoop already logs
		// its failures unconditionally.
		if v.Err != nil && errors.Is(v.Err, chain.ErrLocal) {
			n.log("local fault handling %s from %s (peer not charged): %v", kind, conn.Addr, v.Err)
		}
		// A get-block this node builds and then does not send must not be
		// left standing in the engine's pending map.
		//
		// OnBlockAnnounce writes pending and returns the request in one step,
		// but the request crosses the two gates below before it reaches the
		// wire, and neither used to tell the engine when it discarded one.
		// The announcement then sat there until ReapUnservedBodies charged
		// its announcer ScoreUnservedBody — for a body this node never asked
		// for. wire.md §9 rule 5 prices "announced and would not serve", and
		// no request ever left, so that was never true of anyone. The address
		// charged is an outbound peer's stable listen address, and the score
		// persists with no decay and no unban, so it accumulated.
		unrequested := func() {
			if v.Reply != nil && v.Reply.Kind == KindGetBlock {
				if g, err := UnmarshalGetBlock(v.Reply.Payload); err == nil {
					n.Engine.ForgetUnrequestedBody(conn.Addr, g.ID)
				}
			}
		}
		if v.Err != nil && v.Score <= ScoreProtocolViolation {
			n.log("dropping %s: %v", conn.Addr, v.Err)
			unrequested()
			return
		}
		if n.Peers.Banned(conn.Addr) || n.Peers.BannedKey(conn.PeerKey) {
			n.log("banning %s", conn.Addr)
			unrequested()
			return
		}
		if v.Reply != nil {
			// Bounded so a peer that asks for a large reply and never reads
			// it cannot pin this goroutine — and the reply payload behind it,
			// up to MaxMessageBytes — indefinitely.
			if err := conn.SendDeadline(v.Reply.Kind, v.Reply.Payload,
				time.Now().Add(writeTimeout)); err != nil {
				unrequested()
				return
			}
		}
		if v.Forward {
			// Not always the frame that arrived: a body reassembled from more
			// than one chunk is flooded as an announcement, because the last
			// chunk of a transfer continues nothing at a peer that never
			// opened one (wire.md §8). forwardFrame is the choice, kept
			// separate so both of its branches can be tested.
			fk, fp := forwardFrame(v, kind, payload)
			n.Broadcast(fk, fp, conn.Addr)
		}
	}
}

// Broadcast sends a message to every peer except one.
//
// Flood, with the seen-cache in the engine doing the deduplication. The
// bandwidth cost is O(peers) per message, which is the scaling ceiling named in
// docs/decisions/networking.md §5 — and the first rung up from it is
// announce-request for certificate bodies, which is a protocol tweak rather
// than an architecture change.
func (n *Node) Broadcast(kind MessageKind, payload []byte, except string) {
	n.mu.Lock()
	targets := make([]*Conn, 0, len(n.conns))
	for addr, c := range n.conns {
		if addr == except {
			continue
		}
		targets = append(targets, c)
	}
	n.mu.Unlock()

	for _, c := range targets {
		// SendDeadline sets the deadline and performs the write atomically
		// under c.writeMu, so a concurrent Broadcast or reply on the same
		// connection cannot move the deadline out from under this write
		// — see Conn.SendDeadline.
		if err := c.SendDeadline(kind, payload, time.Now().Add(writeTimeout)); err != nil {
			n.log("send to %s failed: %v", c.Addr, err)
		}
	}
}

// AnnounceBlock gossips a newly mined block, hash-first.
func (n *Node) AnnounceBlock(b *types.Block) {
	ann := BlockAnnounce{Header: b.Header, CertExemplars: b.CertExemplars()}
	n.Broadcast(KindBlockAnnounce, ann.MarshalAnnounce(), "")
}

// AnnounceCertificate gossips a certificate.
func (n *Node) AnnounceCertificate(c *types.Certificate) {
	n.Broadcast(KindCertificate, c.MarshalSSZ(), "")
}

func (n *Node) log(format string, args ...any) {
	if n.Logger != nil {
		n.Logger.Printf(format, args...)
	}
}

// firstGroup renders the ", first <group>" clause, or nothing when no sender
// was recorded. Named because both branches of reportClockSkew need it and a
// report that does not name its suspect gives the operator nothing to act on.
func firstGroup(r SkewReport) string {
	if r.FirstGroup == "" {
		return ""
	}
	return fmt.Sprintf(", first %s", r.FirstGroup)
}
