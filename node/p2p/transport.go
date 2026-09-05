package p2p

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// The transport: TCP, then TLS 1.3 from the standard library.
//
// The security-critical part is deliberately *not* written here. There is no
// custom handshake state machine, no custom AEAD framing and no custom key
// schedule — peer identity is an Ed25519 key carried in a self-signed
// certificate and checked in VerifyPeerCertificate, and everything else is
// crypto/tls. See docs/decisions/networking.md §8: hand-rolling a Noise
// handshake was rejected precisely because it puts custom code on this path.
//
// Certificates are ephemeral and self-signed. There is no certificate authority
// and there is nothing for one to attest: a peer's identity *is* its public
// key, and the only question TLS is being asked is "does this connection belong
// to the key that answered the handshake".

// Identity is a node's network key. It is unrelated to any wallet key: a node
// holds no key material that can move money (I2-L3), and this one signs
// nothing but its own TLS handshake.
type Identity struct {
	priv ed25519.PrivateKey
	cert tls.Certificate
}

// NewIdentity generates a fresh network identity.
func NewIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	cert, err := selfSigned(pub, priv)
	if err != nil {
		return nil, err
	}
	return &Identity{priv: priv, cert: cert}, nil
}

// PublicKey returns the identity's public key.
func (id *Identity) PublicKey() ed25519.PublicKey {
	return id.priv.Public().(ed25519.PublicKey)
}

// String renders a short, stable identifier for logs.
func (id *Identity) String() string {
	pub := id.PublicKey()
	return hex.EncodeToString(pub[:8])
}

func selfSigned(pub ed25519.PublicKey, priv ed25519.PrivateKey) (tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "zycord"},
		// A long validity with no revocation path: the certificate attests
		// nothing except "this connection belongs to this key", which cannot
		// expire in any meaningful sense. Dates are fixed rather than relative
		// so that two nodes with different clocks still connect — clock skew
		// must not be able to partition the network (R1-H2's principle, applied
		// outside consensus).
		NotBefore:             time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// Errors returned by the transport.
var (
	ErrNotEd25519 = errors.New("p2p: peer certificate is not Ed25519")
	ErrNoPeerCert = errors.New("p2p: peer presented no certificate")
	// ErrSelfConnection is returned when the peer that completed the handshake
	// authenticated as this node's own identity — the connection is a loop
	// back to this process.
	//
	// It is decided on the key, not on the dial address, because
	// self-connection is an identity property and an address is only one of its
	// symptoms. A node reaches itself under an address it does not recognise as
	// its own whenever the address is not the one it bound: a second interface,
	// a NAT hairpin, an operator listing this host's public name in --peers, or
	// gossip handing back this node's own advertised listen address. Every one
	// of those ends in a TLS handshake against this identity's key, so the key
	// is the only comparison that sees all of them, and it sees them on both
	// legs: Identity.Dial and Listener.handshake each make the same check, so
	// the outbound slot and the inbound slot are both refused.
	//
	// The check is made *after* Handshake returns and not inside
	// VerifyPeerCertificate. crypto/tls runs VerifyPeerCertificate on the
	// parsed certificate before it verifies the peer's CertificateVerify
	// signature, so inside the callback a public key is only a claim: any
	// host that can answer a TCP connection can replay this node's own
	// certificate — which this node hands to every peer it ever speaks to —
	// and be told "you are me". After a completed handshake the key is
	// authenticated, so this error is at least a statement that someone
	// holds this node's private key over this connection.
	//
	// It is NOT a statement that the address is this node's, and nothing
	// built on it may assume otherwise. An on-path attacker holding none of
	// this node's secrets can answer an honest peer's address and splice the
	// byte stream to this node's own listener; the handshake then completes
	// against this node's own key, CertificateVerify and all. The verdict is
	// then correct about the connection and wrong about the address, and no
	// comparison at this layer can separate the two — a relay to ourselves
	// genuinely is a self-connection. Callers must therefore treat a self
	// verdict as revocable evidence about an address rather than as a fact:
	// Node.selfAddrs holds it for a bounded window and a bounded count for
	// exactly this reason, and an earlier version of this comment claiming
	// the address is retired "for the life of the process" described a
	// permanent, attacker-selectable eviction primitive rather than a guard.
	ErrSelfConnection = errors.New("p2p: peer key is this node's own identity")
	// ErrListenerClosed is returned by Accept once the listener has been
	// closed, and on every call after — matching net.Listener's contract.
	ErrListenerClosed = errors.New("p2p: listener closed")
)

// tlsConfig builds the shared configuration.
//
// InsecureSkipVerify disables *chain* verification, which is correct and not a
// weakening: there is no certificate authority in this system and nothing for
// one to sign. Authentication is done by VerifyPeerCertificate, which extracts
// the peer's Ed25519 key into Conn.PeerKey — the authenticated identity, which
// a reconnect cannot change for free the way it changes Conn.Addr's ephemeral
// source port. Node.serve and Node.SyncFrom key live scoring and bans on it
// (PeerStore.AdjustKey / BannedKey). The persisted PeerStore stays keyed
// on address: it is also the dial store, and an address is dialable where a
// key is not.
func (id *Identity) tlsConfig(onPeerKey func(ed25519.PublicKey)) *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{id.cert},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return ErrNoPeerCert
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return ErrNotEd25519
			}
			// No self-check here: at this point crypto/tls has not yet
			// verified the peer's CertificateVerify, so pub is an unproven
			// claim. See ErrSelfConnection for why that matters and where
			// the check lives instead.
			if onPeerKey != nil {
				onPeerKey(pub)
			}
			return nil
		},
	}
}

// Conn is an authenticated connection to a peer.
type Conn struct {
	net.Conn
	// PeerKey is the peer's Ed25519 identity, established by TLS.
	PeerKey ed25519.PublicKey
	// Addr is the address this connection was made to or from, used for peer
	// scoring and the peer store.
	Addr string
	// slotToken identifies the Listener slot this connection holds, if any.
	// Zero for every outbound connection (Dial never sets it) and for any
	// inbound connection this listener never charged. Release takes this
	// instead of Addr, because Addr is not guaranteed unique per connection —
	// two accepted connections can share an observed RemoteAddr — while a
	// token minted fresh per Accept always is (round 2 review finding).
	slotToken uint64

	// outbound records which side opened this connection, and admittedAt when
	// Node.register admitted it. Both are written once, by register, under
	// Node.mu, and read only under it: they are inputs to the inbound eviction
	// policy (Node.inboundVictimLocked), which is a decision about the
	// served set and therefore belongs to whoever holds that set's lock.
	outbound   bool
	admittedAt time.Time
	// evicted records that Node.register took this connection out of the served
	// set to make room for a newer arrival, so that this connection's own
	// teardown does not delete an entry another connection has since taken over
	// at the same address. Written and read under Node.mu; see Node.retire.
	evicted bool

	// lastUseful is the last time Node.serve applied a positive score to a
	// message on this connection, as Unix nanoseconds; zero means never.
	//
	// It is the "recently useful" half of the inbound eviction policy: a
	// connection that has delivered something this node did not have is
	// evidence rather than occupancy, and it is given up after one that has
	// only ever held a slot open. It is deliberately the *scored* signal and
	// not a byte or frame counter — the connections that policy is about are kept
	// alive by a 9-byte count-0 frame that is scored nothing, so anything
	// counting traffic would rank them as the busiest peers this node has.
	//
	// Atomic because serve writes it outside Node.mu, on the message loop,
	// while register reads it under Node.mu on another goroutine.
	lastUseful atomic.Int64

	// writeMu serialises writes, and every write deadline too.
	// SetWriteDeadline is shadowed below rather than left to the embedded
	// net.Conn, precisely so a deadline can never be set outside this lock:
	// Broadcast used to call it directly on the bare connection, and a second
	// Broadcast racing the first could silently move the deadline governing a
	// write already in flight.
	writeMu sync.Mutex
}

// Send frames and writes a message, under whatever write deadline is
// currently set. SendDeadline is what most callers reaching a connection
// that anything else might also be writing to should use instead.
func (c *Conn) Send(kind MessageKind, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return Frame(c.Conn, kind, payload)
}

// SendDeadline frames and writes a message, first setting the write deadline
// — atomically with the write, under the same lock — so the deadline that
// governs a write is always the one its own caller asked for.
//
// Before this, node.Broadcast called SetWriteDeadline directly on the bare
// connection, outside writeMu. Two goroutines can legitimately write to the
// same peer at once — Broadcast runs from inside every serve goroutine's
// forward path as well as from the miner's announce calls, and a reply can
// land on the same connection at the same moment — so "A sets a deadline, A
// blocks in Send, B sets a later deadline on A's in-flight write" was
// reachable, and silently extended A's timeout. A zero Time clears the
// deadline, exactly as SetWriteDeadline(time.Time{}) does.
func (c *Conn) SendDeadline(kind MessageKind, payload []byte, deadline time.Time) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.Conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	return Frame(c.Conn, kind, payload)
}

// SetWriteDeadline shadows the embedded net.Conn method to take writeMu
// first. Nothing in this codebase calls it directly any more — SendDeadline
// is the sanctioned path — but shadowing it means a future caller that does
// is safe by construction rather than by remembering the convention: it can
// no longer land on a write already in flight under a different deadline.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}

// Receive reads one message.
func (c *Conn) Receive() (MessageKind, []byte, error) { return ReadFrame(c.Conn) }

// Dial connects to a peer and completes the TLS handshake.
func (id *Identity) Dial(addr string, timeout time.Duration) (*Conn, error) {
	var peerKey ed25519.PublicKey
	dialer := &net.Dialer{Timeout: timeout}
	raw, err := tls.DialWithDialer(dialer, "tcp", addr,
		id.tlsConfig(func(pub ed25519.PublicKey) { peerKey = pub }))
	if err != nil {
		return nil, err
	}
	// Handshake complete, so peerKey is authenticated: the peer proved
	// possession of the private key over this connection's transcript. Only
	// now is "this peer is me" a fact rather than a claim.
	if peerKey.Equal(id.PublicKey()) {
		raw.Close()
		return nil, ErrSelfConnection
	}
	return &Conn{Conn: raw, PeerKey: peerKey, Addr: addr}, nil
}

// slotCharge records what a single charged inbound slot needs in order to be
// released correctly: which group it counted against, and which counter
// (held or probationary) it belongs to.
type slotCharge struct {
	group        string
	probationary bool
}

// probationRecord pairs a reserve connection's deadline with the address
// Node.probationLoop needs to find and close it — n.conns is (correctly, and
// unrelated to the token/address distinction here) keyed by address, so
// ExpiredProbation still reports addresses even though the underlying record
// is keyed by token.
type probationRecord struct {
	addr     string
	deadline time.Time
}

// pendingHandshake is what the listener remembers about a TLS handshake it
// has in flight: when it arrived, and who it arrived from.
type pendingHandshake struct {
	token uint64
	group string
}

// Listener accepts authenticated connections.
type Listener struct {
	inner net.Listener
	id    *Identity
	// perSource bounds how many inbound connections a single origin may HOLD.
	// Without it one source fills the inbound slots and crowds out everyone
	// else, which is half an eclipse for the price of a socket (M2-G4).
	perSource int
	// reserve is a small separate allowance for connections that do not hold.
	//
	// Sync opens its own dedicated connection (spec/wire.md §12), and that
	// connection was charged to the same budget as the long-lived gossip
	// connections — so a node whose inbound slots were full by ordinary peering
	// refused the very connection a peer needed in order to catch up. Two
	// classes with opposite lifetimes and opposite purposes sharing one
	// allowance, which is a conflation rather than a policy.
	//
	// The listener cannot ask which class a connection is: it accepts before any
	// frame is exchanged, so there is nothing to declare and nothing to trust if
	// there were. The class is therefore defined by *behaviour* — a reserve
	// connection may exist, but it may not persist. Overstay its window and it
	// is closed.
	//
	// The eclipse bound is unchanged in the dimension that matters: one source
	// still holds at most perSource connections indefinitely. It may in addition
	// churn up to `reserve` short ones, which costs it a fresh handshake every
	// window and buys it nothing durable.
	reserve int
	// probation is how long a reserve connection may live.
	probation time.Duration
	// handshakeTimeout bounds how long an accepted TCP connection has to
	// complete its TLS handshake. See DefaultHandshakeTimeout.
	handshakeTimeout time.Duration

	mu sync.Mutex
	// held counts connections inside perSource; probationary counts those in the
	// reserve, with their deadlines.
	held         map[string]int
	probationary map[string]int
	// classOf and probationEnds are keyed by a token unique to each accepted
	// connection — nextToken, minted once per charged slot — rather than by
	// address.
	//
	// They used to be keyed by addr directly. Two accepted connections can
	// share an observed RemoteAddr (an attacker with a direct IP can bind a
	// specific local port, close, and reconnect from it before this node's
	// Release for the first one runs — no NAT trick needed), and a shared
	// string key meant the second charge's classOf write silently overwrote the
	// first's record instead of adding to it. Release then deleted that one
	// record on whichever connection's disconnect happened to run first; the
	// second connection's ordinary, correct Release call found nothing left to
	// release and no-opped, permanently over-counting held[group] by one per
	// collision — the exact slot leak this token exists to close, just
	// relocated rather than fixed (round 2 review finding). A token minted
	// fresh per charge cannot collide, so two connections sharing an address
	// now each get their own record and their own, independent release.
	classOf       map[uint64]slotCharge
	probationEnds map[uint64]probationRecord
	// nextToken mints the per-connection key classOf/probationEnds use.
	// Starts incrementing from 1, never 0, so a zero-value Conn.slotToken
	// (every outbound connection, which never goes through this listener)
	// can never collide with a real charge and Release(0) is always a safe
	// no-op.
	nextToken uint64
	// refused counts connections turned away for a full budget — a group's
	// perSource+reserve share, or the global maxHandshakes cap.
	//
	// A refusal is the eclipse defence working, so this is a counter and not an
	// alarm — a check that fires for a benign reason is noise with authority.
	// It exists because the refusal was *invisible*: the socket is closed before
	// the TLS handshake and nothing is logged, so at the dialer it is an EOF and
	// at this node it is nothing at all.
	//
	// That cost a real diagnosis. A ten-hour soak recorded 166 sync attempts
	// ending in EOF at a node that could not catch up, and there was no way to
	// tell a refused accept from a severed link — from either end. Two candidate
	// causes, one indistinguishable symptom, and the instrument that separates
	// them is this integer.
	refused int64

	// accepted delivers fully authenticated connections to Accept. Each
	// accepted TCP connection's TLS handshake runs on its own goroutine
	// (see acceptRaw and handshake) rather than inline in Accept, so a
	// connection that completes the TCP handshake and then sends nothing
	// occupies only its own goroutine: it cannot block the raw accept loop
	// from taking the next connection, and it cannot block Accept from
	// returning a connection that finishes its handshake later.
	accepted chan *Conn
	// quit is closed exactly once, when the raw accept loop ends — because
	// Close was called, or the underlying listener errored on its own. Accept
	// and every in-flight handshake goroutine select on it.
	quit      chan struct{}
	closeOnce sync.Once

	// pending tracks raw connections whose TLS handshake is actually in
	// flight, so Close can close them immediately rather than leaving them to
	// run out their handshake timeout — the same "close what you own"
	// discipline Node.Stop already applies to registered connections,
	// extended down into the connections the listener itself is still
	// holding. len(pending) is also what maxHandshakes bounds — see
	// acceptRaw.
	//
	// An entry is removed the instant its handshake finishes, before the
	// goroutine blocks handing the authenticated connection to Accept: a peer
	// that has already proved its identity is not "a handshake in flight" and
	// must not be counted against — or, worse, preempted by — the budget that
	// exists to bound unproven ones.
	//
	// The value carries the connection's slot token — which acceptRaw mints
	// in strictly increasing order and therefore doubles as an arrival
	// sequence — and its address group, which is what victim selection needs
	// (see acceptRaw).
	pendingMu sync.Mutex
	pending   map[net.Conn]pendingHandshake
	// maxHandshakes bounds how many TLS handshakes may be in flight across
	// every address group at once. See DefaultMaxHandshakes.
	maxHandshakes int
	// preempted counts handshakes cut short to make room for a newer arrival
	// once maxHandshakes was reached. Like refused, it is a counter and not
	// an alarm — but unlike refused it is the *only* externally visible trace
	// of the event, since the preempted peer sees an ordinary connection
	// reset and this node logs nothing.
	preempted int64
}

// Listen starts accepting on an address.
func (id *Identity) Listen(addr string, perSource int) (*Listener, error) {
	if perSource <= 0 {
		perSource = 3
	}
	inner, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &Listener{
		inner:            inner,
		id:               id,
		perSource:        perSource,
		reserve:          DefaultInboundReserve,
		probation:        DefaultInboundProbation,
		handshakeTimeout: DefaultHandshakeTimeout,
		maxHandshakes:    DefaultMaxHandshakes,
		held:             map[string]int{},
		probationary:     map[string]int{},
		classOf:          map[uint64]slotCharge{},
		probationEnds:    map[uint64]probationRecord{},
		accepted:         make(chan *Conn),
		quit:             make(chan struct{}),
		pending:          map[net.Conn]pendingHandshake{},
	}
	go l.acceptRaw()
	return l, nil
}

// The reserve, and why these numbers.
//
// Two, because a node catching up talks to one peer at a time and the rotation
// may have a second attempt in flight; more would widen the eclipse surface for
// no gain. Ninety seconds, because a sync round over a long gap is many
// request/response exchanges and must not be cut off mid-catch-up, while an
// attacker holding a slot must re-handshake often enough to be visible and
// rate-limitable. Both are policy, not consensus, and both are guesses that the
// M3 testnet should replace with measurements — they are on the tunable half of
// docs/decisions/testnet-measurements.md.
const (
	DefaultInboundReserve   = 2
	DefaultInboundProbation = 90 * time.Second
	// DefaultHandshakeTimeout bounds how long an accepted TCP connection has
	// to complete its TLS handshake before the slot it holds is reclaimed.
	//
	// Without a bound, a connection that completes the TCP three-way handshake
	// and then sends nothing held its slot — and, before the handshake moved
	// off the shared accept goroutine, the whole listener — forever, for the
	// cost of one SYN/ACK: the cheapest attack in the codebase. Ten seconds is
	// generous for a local TLS 1.3 handshake and short enough that a silent
	// socket is reclaimed quickly; it is on the same tunable footing as the
	// reserve and probation constants above.
	DefaultHandshakeTimeout = 10 * time.Second
	// DefaultMaxHandshakes bounds how many TLS handshakes may be in flight
	// across every address group at once — a global backstop on top of the
	// per-group perSource+reserve bound.
	//
	// Moving the handshake off the shared accept goroutine traded a
	// binary failure for a scalable one: before, one silent connection
	// blocked every accept regardless of how many an attacker had; after,
	// nothing blocks accepting, but each additional distinct address group an
	// attacker controls still pins perSource+reserve more goroutines and file
	// descriptors, each for up to DefaultHandshakeTimeout — and the per-group
	// bound alone does nothing to stop that total from growing with the
	// number of groups (round 2 review finding, confirmed by measurement:
	// 4000 concurrent silent connections cost about 3.6KB of heap each and
	// did not slow an honest peer's own accept — cheap per unit, unbounded in
	// total). This caps the sum regardless of how many groups an attacker can
	// present, the same way perSource caps one group's share alone.
	//
	// 512 is generous headroom above ordinary operation — legitimate
	// concurrent handshakes should rarely approach even honestSteadyStateConns,
	// MaxInbound+MaxOutbound's default of 40 at once (the honest steady state
	// and not maxConnections' adversarial 48 — see magnitudes.go), since a real
	// handshake completes
	// in well under a second — while still bounding an attacker's worst case
	// to a fixed, small multiple of goroutines and sockets rather than a
	// number that grows with however much address diversity they control.
	//
	// What happens *at* the cap is the load-bearing half of this decision,
	// and it is preemption rather than refusal. A cap that refuses the
	// newcomer hands the accept stall back: hold the cap full of silent
	// connections — 512 of them, about 103 distinct /16 groups at
	// perSource+reserve each, re-established every handshakeTimeout — and
	// every honest peer is locked out for as long as the flood lasts, which
	// is "one silent TCP connection halts all inbound accepts" again with a
	// larger constant in front of it. Preemption keeps the same ceiling on
	// goroutines and file descriptors while restoring what that fix was about: a
	// connection that says nothing cannot stop one that would.
	//
	// What preemption buys, stated as a price rather than a guarantee. To
	// lock an honest peer out, an attacker must hold every slot for the
	// whole time that peer's handshake takes. Against refusal that costs
	// maxHandshakes / handshakeTimeout — about 51 connections a second here,
	// because a silent connection holds its slot for the full ten seconds.
	// Against preemption the attacker must instead keep replacing its own
	// connections faster than the honest handshake completes, which costs
	// maxHandshakes / that handshake's duration: roughly 5,700 connections a
	// second against a peer on a 100ms round trip. Two orders of magnitude,
	// not an impossibility — and the peer it costs the most to protect is
	// the slowest one, which is also the one a naive oldest-first rule would
	// have handed over first. victimLocked spends the rest of the margin on
	// exactly that: it takes from the address group holding the most
	// handshakes, so a flood needing a hundred groups never picks the honest
	// peer arriving alone in its own. What remains is an attacker with
	// enough address diversity to hold the cap one connection per group,
	// which is a far larger asset than the flood this started with.
	DefaultMaxHandshakes = 512
)

// SetProbation overrides the reserve window. For tests: a real node has no
// reason to change it at runtime.
func (l *Listener) SetProbation(d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.probation = d
}

// SetMaxHandshakes overrides the global in-flight handshake cap. For tests: a
// real node has no reason to change it at runtime.
//
// Clamped to at least one. A cap of zero would not mean "accept nothing" —
// there is no handshake to preempt when the map is empty, so it would mean
// "admit everything", silently turning the bound off in the one direction a
// caller passing zero cannot have intended.
func (l *Listener) SetMaxHandshakes(n int) {
	if n < 1 {
		n = 1
	}
	l.pendingMu.Lock()
	defer l.pendingMu.Unlock()
	l.maxHandshakes = n
}

// Addr returns the bound address.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// Close stops accepting and immediately closes every connection currently
// mid-handshake — the same "close what you own" step Node.Stop takes for
// registered connections, extended down into the connections the listener
// itself is still holding.
//
// The raw listener is closed first, before the pending sweep, which narrows
// — though does not fully close — a race an earlier version of this method
// had: once l.inner is closed, every call to l.inner.Accept() already
// blocked or made after returns an error immediately, so acceptRaw cannot
// admit anything new by the time the sweep below runs. A connection acceptRaw
// had *already* accepted off the kernel's backlog and was mid-flight through
// its own admission logic at the exact instant Close ran can still slip past
// this narrower window and get a handshake goroutine after Close returns
// (round 2 review finding). That goroutine is still bounded by
// DefaultHandshakeTimeout and its eventual Release is unaffected — it was
// never involved in any collision — so this is a delayed-cleanup gap, not an
// unbounded leak or an accounting error: Close/Stop returning is not a hard
// guarantee that zero handshake goroutines remain, only that none of them can
// block anything Node.wg waits on.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() { close(l.quit) })
	err := l.inner.Close()
	l.pendingMu.Lock()
	for raw := range l.pending {
		raw.Close()
	}
	l.pendingMu.Unlock()
	return err
}

// Accept returns the next authenticated connection, refusing sources that
// already hold their share of the inbound slots.
//
// The TLS handshake for each accepted connection runs on its own goroutine
// (see acceptRaw and handshake) rather than here, so this call is nothing
// more than a receive off a channel: a connection that never completes its
// handshake cannot delay one that does, and cannot delay the next raw TCP
// accept either.
func (l *Listener) Accept() (*Conn, error) {
	select {
	case c := <-l.accepted:
		return c, nil
	case <-l.quit:
		return nil, ErrListenerClosed
	}
}

// acceptRaw pulls raw TCP connections and hands each to its own handshake
// goroutine. It is the only thing that ever calls the underlying listener's
// Accept, and it never itself touches TLS or blocks on anything but the
// kernel accept(2) call — which is what the accept stall needed: one connection that
// completes the TCP handshake and sends nothing can no longer block the next
// connection from even being accepted, let alone from being handed to a peer
// whose handshake actually completes.
func (l *Listener) acceptRaw() {
	for {
		raw, err := l.inner.Accept()
		if err != nil {
			l.closeOnce.Do(func() { close(l.quit) })
			return
		}

		addr := raw.RemoteAddr().String()
		group := AddressGroup(addr)

		l.mu.Lock()
		l.expireProbationLocked(group)
		var probationary, refused bool
		var token uint64
		switch {
		case l.held[group] < l.perSource:
			l.held[group]++
		case l.probationary[group] < l.reserve:
			l.probationary[group]++
			probationary = true
		default:
			refused = true
			l.refused++
		}
		if !refused {
			// A token minted here, not the address, is what classOf and
			// probationEnds are keyed on — see the struct's comment for why:
			// two connections can share addr, and a shared string key let one
			// connection's Release delete the record a second, unrelated
			// connection's Release still needed.
			l.nextToken++
			token = l.nextToken
			l.classOf[token] = slotCharge{group: group, probationary: probationary}
			if probationary {
				l.probationEnds[token] = probationRecord{addr: addr, deadline: time.Now().Add(l.probation)}
			}
		}
		l.mu.Unlock()
		if refused {
			raw.Close()
			continue
		}

		// The global handshake cap (maxHandshakes) is checked and charged
		// here, synchronously in this single accept goroutine, rather than
		// inside handshake itself. A check-then-spawn split would let a burst
		// of connections all pass the check before any of their handshake
		// goroutines had registered themselves, overshooting the cap during
		// exactly the burst it exists to bound — acceptRaw is the one
		// goroutine that ever decides to admit a connection, so charging the
		// same map that tracks in-flight handshakes (pending) before spawning
		// is what keeps len(pending) an accurate, race-free count at every
		// instant, not just between bursts.
		//
		// Reaching the cap preempts the *oldest* handshake still in flight
		// rather than refusing the newcomer, and that direction is the whole
		// point. Refusing at the cap reproduces the accept stall — "one silent TCP
		// connection halts all inbound accepts" — for the price of
		// maxHandshakes sockets instead of one: a silent connection completes
		// the TCP handshake and then says nothing for handshakeTimeout, so an
		// attacker holding the cap full of them locks every honest peer out
		// of this node entirely, which is the exact symptom that fix exists to
		// remove. Measured on this code: with the cap held by silent
		// connections, a peer offering a real, valid TLS handshake got EOF.
		//
		// Preemption is self-targeting, which is why it is safe. Occupying a
		// slot at all requires *being* old — concurrency is arrival rate
		// times handshake lifetime, so an attacker can only hold the cap full
		// by holding connections open, and every one it holds open ages past
		// the honest handshakes that complete in milliseconds. To make an
		// honest connection the oldest in the map, an attacker would have to
		// have no connection older than it, i.e. have just released every
		// slot it held. The bound is preserved either way: len(pending) never
		// exceeds maxHandshakes, so the goroutine and file-descriptor ceiling
		// the cap exists for is unchanged.
		l.pendingMu.Lock()
		var victim net.Conn
		if len(l.pending) >= l.maxHandshakes {
			// victimLocked cannot return nil here: reaching this line means
			// the map holds at least maxHandshakes entries, and
			// SetMaxHandshakes keeps that at least 1.
			victim = l.victimLocked()
			delete(l.pending, victim)
			l.preempted++
		}
		l.pending[raw] = pendingHandshake{token: token, group: group}
		l.pendingMu.Unlock()
		if victim != nil {
			// Closing the socket is what ends the preempted handshake: its
			// own Handshake() call fails, and its goroutine takes the
			// ordinary failure path — Release(token), close, return. It is
			// already out of pending, so its own deferred removal is a
			// no-op and the count stays exact.
			victim.Close()
		}

		go l.handshake(raw, addr, token)
	}
}

// victimLocked picks the handshake to give up so a new arrival can be
// admitted: the oldest one belonging to whichever address group holds the
// most handshakes in flight. Callers hold pendingMu.
//
// Group first, age second, and the order matters. Age alone says "evict the
// slowest", and the slowest connection in the map is a distant honest peer on
// a 100ms round trip, not a local attacker who controls its own connection
// lifetime and can always arrive later: an attacker that churns — connect,
// hold briefly, reset — keeps every one of its handshakes newer than an
// honest peer's, and pure oldest-first hands it that peer every time. Group
// share is the signal that does not invert, because holding the cap requires
// *breadth* — perSource+reserve bounds one group to five in flight, so an
// attacker filling 512 slots needs about a hundred groups at five apiece
// while the honest peer arrives as its group's only connection. The heaviest
// group is therefore the attacker's, and the singleton is spared.
//
// This narrows the residual rather than removing it, and the comment on
// DefaultMaxHandshakes says where the edge still is.
//
// A linear scan, deliberately: it runs only on the accept that finds the cap
// already full, over at most maxHandshakes entries — a few hundred
// comparisons on a path that is by definition already under attack. Keeping
// an index would make the common case, which does not scan at all, pay for
// the rare one.
func (l *Listener) victimLocked() net.Conn {
	share := make(map[string]int, len(l.pending))
	for _, p := range l.pending {
		share[p.group]++
	}
	var victim net.Conn
	var best pendingHandshake
	var bestShare int
	for raw, p := range l.pending {
		s := share[p.group]
		if victim == nil || s > bestShare || (s == bestShare && p.token < best.token) {
			victim, best, bestShare = raw, p, s
		}
	}
	return victim
}

// Preempted reports how many in-flight handshakes this listener cut short to
// admit a newer arrival once the global handshake cap was reached.
//
// Read it the way Refused is read, and for the same reason: the peer on the
// other end sees an ordinary connection reset, indistinguishable from a
// network fault, and this node logs nothing. A rising count means the cap is
// binding — legitimate load has outgrown DefaultMaxHandshakes, or something
// is holding handshakes open — and a flat one means it never has.
func (l *Listener) Preempted() int64 {
	l.pendingMu.Lock()
	defer l.pendingMu.Unlock()
	return l.preempted
}

// handshake completes the TLS handshake for one accepted connection off the
// shared acceptRaw goroutine, and delivers the result to Accept. raw is
// already registered in l.pending by the time this runs — see acceptRaw.
func (l *Listener) handshake(raw net.Conn, addr string, token uint64) {
	// unpend takes this connection out of the in-flight handshake budget. It
	// is called explicitly the moment the handshake finishes — not left to
	// the defer — so that the wait to hand the connection to Accept is not
	// counted as a handshake still running, and so that an already
	// authenticated peer can never be chosen as a preemption victim. The
	// defer is the failure-path half of the same job; calling it twice is
	// harmless.
	var unpendOnce sync.Once
	unpend := func() {
		unpendOnce.Do(func() {
			l.pendingMu.Lock()
			delete(l.pending, raw)
			l.pendingMu.Unlock()
		})
	}
	defer unpend()

	// Bounds the handshake itself (DefaultHandshakeTimeout) — belt to this
	// goroutine's braces. Running off the shared accept goroutine already
	// stops a silent connection from blocking anyone else's accept; this
	// stops it from holding its own slot forever.
	raw.SetDeadline(time.Now().Add(l.handshakeTimeout))

	var peerKey ed25519.PublicKey
	server := tls.Server(raw, l.id.tlsConfig(func(pub ed25519.PublicKey) { peerKey = pub }))
	if err := server.Handshake(); err != nil {
		l.Release(token)
		raw.Close()
		return
	}
	// The acceptor's half of the self guard, on the same authenticated
	// footing as Identity.Dial's. Releasing here means the slot this
	// connection was charged is given back and nothing is handed to Accept,
	// so serve never runs and the ephemeral source address is never recorded
	// by PeerStore.MarkConnected.
	if peerKey.Equal(l.id.PublicKey()) {
		l.Release(token)
		raw.Close()
		return
	}
	// The handshake deadline is not the connection's deadline: node.go's
	// serve loop manages its own read and write deadlines from here on. A
	// stale short deadline left in place would cut a freshly authenticated
	// connection off mid-first-message.
	raw.SetDeadline(time.Time{})
	unpend()

	conn := &Conn{Conn: server, PeerKey: peerKey, Addr: addr, slotToken: token}
	select {
	case l.accepted <- conn:
	case <-l.quit:
		// Accept will never read this: the listener is closing. Undo the
		// slot exactly as a failed handshake would.
		l.Release(token)
		conn.Close()
	}
}

// Refused reports how many inbound connections this listener has turned away
// for a full budget, since it started.
//
// Read it next to the sync failures at the *other* end. A node reporting EOF on
// every sync attempt and a peer reporting a rising refusal count are one story;
// the same EOFs against a flat count are a different one, and before this
// existed the two were the same observation.
func (l *Listener) Refused() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.refused
}

// Release frees the inbound slot a single connection was charged, identified
// by the token Accept minted for it (Conn.slotToken) rather than by address —
// see the Listener struct's comment on classOf for why a shared address
// cannot be the key. token 0 (every outbound Conn's zero value, and any
// connection this listener never charged) is always a safe no-op: nextToken
// never mints 0.
func (l *Listener) Release(token uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	charge, known := l.classOf[token]
	if !known {
		return
	}
	delete(l.classOf, token)
	if charge.probationary {
		delete(l.probationEnds, token)
		if l.probationary[charge.group] > 0 {
			l.probationary[charge.group]--
		}
		return
	}
	if l.held[charge.group] > 0 {
		l.held[charge.group]--
	}
}

// ExpiredProbation returns reserve connections that have outstayed their window.
//
// The caller closes them: the listener does not own the connections it handed
// out, and a listener that reached into another goroutine's socket would be a
// worse design than a caller that asks. Addresses, not tokens: Node.conns —
// unrelated to the token/address distinction the rest of this file makes — is
// keyed by address, which is what Node.probationLoop needs to find and close
// the right connection.
func (l *Listener) ExpiredProbation() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	now := time.Now()
	for _, rec := range l.probationEnds {
		if now.After(rec.deadline) {
			out = append(out, rec.addr)
		}
	}
	return out
}

// expireProbationLocked reclaims reserve slots from connections that are gone.
//
// It used to reclaim them from connections that were merely *late*, deleting
// the deadline and the class along with the count — and the deadline is the
// reaper's only record. `ExpiredProbation` reads that map; `Node.probationLoop`
// closes what it names. Erasing an entry therefore did not enforce the window,
// it **forgave** it: the connection stayed open, unclosable because nothing
// remembered it was overdue, and the slot it had vacated was free to be taken
// again.
//
// A squatter only had to outlast its window until the next connection arrived
// from its own address group — which, on a network where that group is dialling
// anyway, is immediate. One group could hold unbounded persistent inbound
// connections: the eclipse bound this defence imposes, dismantled by the
// bookkeeping meant to enforce it.
//
// So an overdue connection keeps its record until it is actually closed, and
// `Release` is the only thing that frees a slot. A group that has filled its
// reserve with overdue connections waits for the reaper — at most one sweep —
// which is the delay "may not persist" is supposed to cost it.
func (l *Listener) expireProbationLocked(group string) {
	now := time.Now()
	for _, rec := range l.probationEnds {
		if !now.After(rec.deadline) || AddressGroup(rec.addr) != group {
			continue
		}
		// Deliberately nothing. The entry is what makes this connection
		// closable, and the slot returns when the close does.
		_ = now
	}
}
