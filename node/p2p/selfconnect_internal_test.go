package p2p

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestSelfConnectionIsRefusedByIdentityNotByAddress pins the mechanism of the
// self-connection guard: a connection is refused because the peer key on the
// other end is this node's own, not because the dial string matched the bound
// address.
//
// The listener binds the wildcard and the dial goes to a loopback literal, so
// ListenAddr() ("0.0.0.0:port") does not equal the dialled address and the
// cheap address comparison in dialTargets provably cannot be what refuses it.
// That is the general case the issue is really about — a second interface, a
// NAT hairpin, an operator naming this host in --peers, or gossip returning
// this node's own advertised address all arrive under an address the node
// does not recognise as its own.
func TestSelfConnectionIsRefusedByIdentityNotByAddress(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := id.Listen("0.0.0.0:0", 4)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	self := net.JoinHostPort("127.0.0.1", port)
	if self == ln.Addr().String() {
		t.Fatalf("the dialled address %q must differ from the bound address %q, "+
			"or an address comparison could account for the refusal", self, ln.Addr())
	}

	if _, err := id.Dial(self, 2*time.Second); !errors.Is(err, ErrSelfConnection) {
		t.Fatalf("dialling own identity at %q: got %v, want ErrSelfConnection", self, err)
	}

	// The other half: the acceptor refused too, so no inbound slot is left
	// charged and nothing was handed to Accept. Without the acceptor-side
	// refusal the dialer's rejection alone would still leave this node holding
	// an inbound slot against itself.
	deadline := time.Now().Add(2 * time.Second)
	for {
		ln.mu.Lock()
		// classOf holds one entry per outstanding charge; held/probationary
		// keep a zero-valued group key after a release, so they count groups
		// ever seen rather than slots still charged.
		charged := len(ln.classOf)
		ln.mu.Unlock()
		if charged == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d inbound slot(s) still charged after a refused self-connection", charged)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The check must not fire for a benign reason: a different identity
	// dialling the same listener at the same address still connects.
	other, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	c, err := other.Dial(self, 2*time.Second)
	if err != nil {
		t.Fatalf("a peer that is not this node must still connect at %q: %v", self, err)
	}
	c.Close()
}

// TestASelfAddressIsRetiredFromTheDialSetAndNeverProven pins the slot half of
// the same guard: one dial round is enough to learn that an address is this process,
// after which the address is not a dial candidate at all, and it never
// reaches MarkConnected — which is what would have made it proven evidence
// and the last entry evicted, permanently.
func TestASelfAddressIsRetiredFromTheDialSetAndNeverProven(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := id.Listen("0.0.0.0:0", 4)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	self := net.JoinHostPort("127.0.0.1", port)

	peers, err := NewPeerStore(filepath.Join(t.TempDir(), "peers.json"))
	if err != nil {
		t.Fatal(err)
	}
	// A second, honest candidate in a different /16, so the round that
	// discards the self address can be seen handing the slot to someone.
	const honest = "203.0.113.7:9999"
	peers.Add(self)
	peers.Add(honest)
	// The honest candidate carries one failure too, so that after the round
	// below the two entries are indistinguishable on score, evidence rank and
	// failure count, and the sort falls through to the address tiebreak —
	// which the self address wins ("1..." < "2..."). Without this, the
	// MarkFailed that a refused self-dial also earns would be enough on its
	// own to demote the self address, and the assertion that it is *excluded*
	// would pass with the exclusion deleted.
	peers.MarkFailed(honest)

	n := NewNode(id, &Engine{}, peers, 1)
	// Exactly one slot, so "the freed slot goes to a real peer" is a claim
	// the test can actually refute. With eight slots both candidates are
	// selected in both worlds and the assertion below would hold with or
	// without the fix. The self address also wins that single slot on the
	// address tiebreak ("1..." < "2..."), so nothing else can account for
	// the handover.
	n.MaxOutbound = 1
	n.listener = ln

	targets := n.dialTargets()
	if !contains(targets, self) {
		t.Fatalf("before any dial the self address is indistinguishable from any other and must be a candidate; got %v", targets)
	}
	n.topUp()

	n.mu.Lock()
	until, learned := n.selfAddrs[self]
	n.mu.Unlock()
	if !learned {
		t.Fatalf("one refused dial did not retire %q", self)
	}
	// The exclusion is a window, not a life sentence: a self-verdict can be
	// arranged by an on-path attacker relaying an honest address to this
	// node's own listener, and a permanent entry would delete that honest
	// peer for the rest of the process.
	if d := time.Until(until); d <= 0 || d > SelfAddrExclusion {
		t.Fatalf("self address %q must be excluded for a bounded window, got %s", self, d)
	}

	targets = n.dialTargets()
	if contains(targets, self) {
		t.Fatalf("self address %q was chosen again after being proved to be this node: %v", self, targets)
	}
	// The slot is not merely denied to the self address, it is handed on in
	// the same round: exclusion happens before the diversity and per-source
	// budgets are counted.
	if !contains(targets, honest) {
		t.Fatalf("the freed slot did not go to the honest candidate: %v", targets)
	}

	p, ok := peers.Get(self)
	if !ok {
		t.Fatal("self address vanished from the store")
	}
	if p.LastSeen != 0 {
		t.Fatalf("self address reached MarkConnected (last_seen=%d), which makes it proven and the last thing evicted", p.LastSeen)
	}
	if p.Failures == 0 {
		t.Fatal("a dial that did not produce a peer must still be scored as a failure")
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// TestASelfVerdictRequiresTheKeyNotJustItsPublicHalf pins the security
// property of where the guard is made: ErrSelfConnection is a statement
// about possession of this node's private key, not about a public key
// appearing in a certificate.
//
// The distinction is load-bearing because a self-verdict is *permanent* for
// the process — Node.topUp retires the address into selfAddrs and the dial
// selector excludes it from every later round. crypto/tls calls
// VerifyPeerCertificate on the parsed certificate before it verifies the
// peer's CertificateVerify signature, so a check made inside that callback
// accepts an unproven claim: this node hands its own certificate to every
// peer it ever speaks to, and any host that can answer a TCP connection can
// replay those bytes. That would let anyone briefly on the path to an honest
// address delete that address from this node's dial set for good — a
// targeted eviction strictly stronger than dropping its packets, which only
// earns a retryable MarkFailed.
//
// The server here presents a certificate carrying the victim's public key,
// signed by — and served with — a key that is not the victim's. It is
// exactly what a replay of the victim's own certificate looks like to the
// callback, and it must NOT be read as a self-connection.
func TestASelfVerdictRequiresTheKeyNotJustItsPublicHalf(t *testing.T) {
	victim, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	_, impostorPriv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "zycord"},
		NotBefore:             time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2999, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, victim.PublicKey(), impostorPriv)
	if err != nil {
		t.Fatal(err)
	}
	forged := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: impostorPriv}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tls.Server(c, &tls.Config{
			Certificates:       []tls.Certificate{forged},
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
			ClientAuth:         tls.RequireAnyClientCert,
		}).Handshake()
	}()

	if _, err := victim.Dial(ln.Addr().String(), 3*time.Second); errors.Is(err, ErrSelfConnection) {
		t.Fatal("a peer that does not hold this node's private key was accepted as this node, " +
			"which permanently retires the address it answered from")
	}
}

// TestARelayedAddressEarnsASelfVerdictThatExpires pins the bound that the
// guard needs in order not to be an eviction primitive.
//
// The self verdict cannot be made unforgeable, and this test is the proof of
// that rather than a workaround for it. An on-path attacker holding none of
// this node's secrets answers an honest peer's address and splices the byte
// stream to this node's own listener. The handshake then genuinely completes
// against this node's own key, CertificateVerify and all, so
// ErrSelfConnection is the *correct* verdict about the connection and the
// wrong one about the address: at the identity layer a relay to ourselves is
// a self-connection, and no comparison can separate them.
//
// So what must be bounded is the permanence. A verdict that lasted the life
// of the process would delete an honest peer from this node's dial set
// forever, outliving the attacker's presence on the path — a transient
// capability turned into a durable eclipse assist, strictly more than
// dropping that address's packets buys. The window is what stops that, and
// this test pins that the window exists, is applied, and ends.
func TestARelayedAddressEarnsASelfVerdictThatExpires(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := id.Listen("127.0.0.1:0", 4)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// The attacker's splice. It holds no key of any kind: it answers on an
	// address of its own and copies bytes both ways to this node's listener.
	relay, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	go func() {
		for {
			down, err := relay.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				down.Close()
				continue
			}
			go func() { io.Copy(up, down); up.Close() }()
			go func() { io.Copy(down, up); down.Close() }()
		}
	}()

	// Stand-in for an honest peer's address: it is not this node's, and this
	// node has no way to know the bytes are being relayed.
	honestLooking := relay.Addr().String()
	if honestLooking == ln.Addr().String() {
		t.Fatal("the relay must answer on an address of its own")
	}

	peers, err := NewPeerStore(filepath.Join(t.TempDir(), "peers.json"))
	if err != nil {
		t.Fatal(err)
	}
	peers.Add(honestLooking)
	n := NewNode(id, &Engine{}, peers, 1)
	n.MaxOutbound = 1
	n.listener = ln

	if _, err := id.Dial(honestLooking, 3*time.Second); !errors.Is(err, ErrSelfConnection) {
		t.Fatalf("a relay to this node's own listener is a genuine self-connection; got %v", err)
	}

	n.topUp()
	n.mu.Lock()
	until, held := n.selfAddrs[honestLooking]
	n.mu.Unlock()
	if !held {
		t.Fatalf("the relayed address %q was not held out of the dial set at all", honestLooking)
	}
	if time.Until(until) > SelfAddrExclusion {
		t.Fatalf("the exclusion window for %q exceeds SelfAddrExclusion", honestLooking)
	}
	if contains(n.dialTargets(), honestLooking) {
		t.Fatalf("the relayed address is still a candidate inside its window: %v", n.dialTargets())
	}

	// The attacker leaves the path. The honest address must come back on its
	// own, without a restart — that is the whole difference between a bounded
	// window and a permanent deletion.
	n.mu.Lock()
	n.selfAddrs[honestLooking] = time.Now().Add(-time.Second)
	n.mu.Unlock()
	if !contains(n.dialTargets(), honestLooking) {
		t.Fatalf("the honest address %q did not return to the dial set after its exclusion expired", honestLooking)
	}
	n.mu.Lock()
	_, stillThere := n.selfAddrs[honestLooking]
	n.mu.Unlock()
	if stillThere {
		t.Fatal("an expired exclusion must be pruned, not merely ignored")
	}
}

// TestTheSelfExclusionSetIsBounded pins that an attacker with breadth cannot
// grow this node's per-process exclusion map without limit, and — the half
// that matters more — that filling it does not make the entries already in it
// permanent. Evicting the entry closest to expiring is what keeps a full map
// from becoming a durable one.
func TestTheSelfExclusionSetIsBounded(t *testing.T) {
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	peers, err := NewPeerStore(filepath.Join(t.TempDir(), "peers.json"))
	if err != nil {
		t.Fatal(err)
	}
	n := NewNode(id, &Engine{}, peers, 1)

	first := "198.51.100.1:1"
	n.retireSelfAddr(first)
	// Backdate it, so that it is strictly the earliest-expiring entry.
	//
	// Without this the test asserts nothing about the eviction *rule*: the
	// fill loop below runs tight enough that every insert reads the same
	// clock value, `until.Before(soonest)` is false on a tie, and the victim
	// falls out of randomised map iteration — "evict earliest-expiring"
	// degrades to "evict at random" and this test fails on correct code
	// about one run in forty. Real entries arrive from topUp at most
	// MaxOutbound per round and seconds apart, so their deadlines are
	// distinct; the tie is an artefact of the loop, not of the rule.
	//
	// It is fixed here and NOT by giving retireSelfAddr an address tiebreak,
	// which would hand the attacker the choice of victim.
	n.mu.Lock()
	n.selfAddrs[first] = time.Now().Add(SelfAddrExclusion - time.Hour)
	n.mu.Unlock()
	for i := 0; i < maxSelfAddrs*3; i++ {
		n.retireSelfAddr(net.JoinHostPort("198.51.100.2", strconv.Itoa(1000+i)))
	}
	n.mu.Lock()
	size := len(n.selfAddrs)
	_, firstSurvived := n.selfAddrs[first]
	n.mu.Unlock()
	if size > maxSelfAddrs {
		t.Fatalf("the self-exclusion set grew to %d, above the cap of %d", size, maxSelfAddrs)
	}
	if firstSurvived {
		t.Fatal("the earliest-expiring entry must be the one evicted at the cap, " +
			"or an attacker fills the map early and every later entry — including a real one — is never recorded")
	}
}
