package p2p

import (
	"crypto/ed25519"
	"encoding/binary"
	"testing"
)

// identityKey builds a distinct, syntactically valid Ed25519 public key for
// index i. The bytes are not a real key — AdjustKey treats the argument as an
// opaque identifier and never verifies it, so a real handshake is not needed
// to exercise the store. That is also the attacker's position: minting one of
// these costs a keygen and a self-signed certificate, which is to say
// nothing.
func identityKey(i int) ed25519.PublicKey {
	k := make(ed25519.PublicKey, ed25519.PublicKeySize)
	binary.BigEndian.PutUint64(k, uint64(i))
	return k
}

func bannedCount(ps *PeerStore) (banned, total int) {
	ps.identityMu.Lock()
	defer ps.identityMu.Unlock()
	for _, e := range ps.identity {
		if e.score <= ScoreBanThreshold {
			banned++
		}
	}
	return banned, len(ps.identity)
}

// TestIdentityStoreIsBounded is the identity store's second review finding: the live,
// unpersisted identity-keyed store AdjustKey/BannedKey introduced had no cap.
// Ed25519 keygen and a self-signed cert are free, and AdjustKey is called on
// every scored message before a connection is even evaluated for
// disconnection, so one throwaway TLS connection plus one throwaway message
// planted a permanent entry — the same unbounded-growth shape the address-keyed
// store had, reopened here in a new keyspace.
//
// Internal test: the identity store deliberately exposes nothing but
// AdjustKey/BannedKey — it is not the persisted, inspectable address store —
// so pinning "the store stayed bounded" needs direct access to ps.identity.
func TestIdentityStoreIsBounded(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxIdentities*4; i++ {
		ps.AdjustKey(identityKey(i), ScoreInvalidMessage)
	}
	if _, total := bannedCount(ps); total > MaxIdentities {
		t.Fatalf("store holds %d identities after %d throwaway arrivals, want at most %d (the cap): "+
			"unbounded growth (round 2 review finding)", total, MaxIdentities*4, MaxIdentities)
	}
}

// TestIdentityCapEvictsWhatNoReaderConsults pins the *direction* of that cap's
// eviction, which the first version of the fix had backwards.
//
// This store has exactly one reader — BannedKey, which asks
// `score <= ScoreBanThreshold`. An entry above the threshold answers that
// question with "no", which is the same answer a key that was never stored at
// all gets: it is worth nothing to keep. The lowest-scoring entry is the one
// record the store exists to hold. Evicting lowest-score-first therefore spent
// the whole MaxIdentities budget on entries nobody ever reads and threw away
// the ones that decide something.
//
// The direction was inherited from the address-keyed store, where it is right
// for the opposite reason: that store's readers pick peers to *dial*, so its
// worst entry is its least useful one. A retention policy copied from a store
// that selects into a store that refuses comes out inverted.
func TestIdentityCapEvictsWhatNoReaderConsults(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}

	// A banned identity, and a store otherwise full of well-behaved ones.
	banned := identityKey(0)
	ps.AdjustKey(banned, ScoreProtocolViolation)
	ps.AdjustKey(banned, ScoreProtocolViolation)
	if !ps.BannedKey(banned) {
		t.Fatal("setup: two protocol violations did not reach the ban threshold")
	}
	for i := 1; i < MaxIdentities; i++ {
		ps.AdjustKey(identityKey(i), ScoreUsefulMessage)
	}

	// One more arrival, with the store exactly full. The ban must not be what
	// makes room for it.
	ps.AdjustKey(identityKey(MaxIdentities), ScoreUsefulMessage)
	if !ps.BannedKey(banned) {
		t.Fatal("a banned identity was evicted to admit a well-behaved newcomer: the only " +
			"entry BannedKey ever answers yes for was dropped in favour of entries it " +
			"always answers no for")
	}
	if _, total := bannedCount(ps); total > MaxIdentities {
		t.Fatalf("store holds %d identities, want at most %d", total, MaxIdentities)
	}
}

// TestBanSurvivesFreeIdentityChurn is the attack the eviction direction
// decides. An attacker's identities cost nothing, so it can present as many as
// it likes; the question is what each one buys.
//
// Under lowest-score-first eviction it bought a ban: MaxIdentities throwaway
// identities, one cheap scored message each, walked every banned entry out of
// the store and left it holding 4096 records of which none were banned. Under
// the ordering this pins, a cheap arrival cannot displace an entry worth more
// than it is, so the same flood buys nothing at all — and the same is true of
// ordinary honest gossip churn, which is the non-adversarial half of the same
// problem: a long-running node meets far more than MaxIdentities well-behaved
// identities, and those must not be able to erase its bans either.
func TestBanSurvivesFreeIdentityChurn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		delta int
	}{
		{"cheap misbehaviour", ScoreInvalidMessage},
		{"ordinary honest gossip", ScoreUsefulMessage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps, err := NewPeerStore("")
			if err != nil {
				t.Fatal(err)
			}
			banned := identityKey(0)
			ps.AdjustKey(banned, ScoreProtocolViolation)
			ps.AdjustKey(banned, ScoreProtocolViolation)
			if !ps.BannedKey(banned) {
				t.Fatal("setup: identity not banned")
			}

			for i := 1; i <= MaxIdentities*2; i++ {
				ps.AdjustKey(identityKey(i), tc.delta)
			}

			if !ps.BannedKey(banned) {
				t.Fatalf("%d churned identities at %d points each erased a standing ban: "+
					"the store can be walked empty of the only entries it exists to hold",
					MaxIdentities*2, tc.delta)
			}
			if _, total := bannedCount(ps); total > MaxIdentities {
				t.Fatalf("store holds %d identities, want at most %d", total, MaxIdentities)
			}
		})
	}
}

// TestIdentityBanningSurvivesAFullStore is the failure the *first* attempt at
// bounding this store's churn walked into, and the reason a newcomer is now
// always admitted rather than weighed against the entry it would displace.
//
// That rule read as the tighter one: only a newcomer worth more than the
// cheapest entry held may displace it, so evicting a ban costs a ban. What it
// actually built was a door that locks from the inside. Fill the store with
// entries at the ban threshold and no first delta a newcomer can have — -20,
// -50, +1 — is ever worth more than -100, so nothing is admitted again;
// nothing here expires, so nothing ever unlocks it; and identity banning is
// off for the life of the process. The bill was 4096 connections and 20,480
// invalid messages, which one address can pay sequentially in minutes: a
// single invalid message is not a protocol violation and does not disconnect
// (see Node.serve), so five of them per identity reach the threshold on one
// connection each.
//
// This test is the one the four tests around it did not write, which is
// exactly how that shipped.
func TestIdentityBanningSurvivesAFullStore(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}

	// The cheapest fill that puts every entry at the ban threshold.
	for i := 0; i < MaxIdentities; i++ {
		for j := 0; j < 5; j++ {
			ps.AdjustKey(identityKey(i), ScoreInvalidMessage)
		}
	}
	if banned, total := bannedCount(ps); banned != total || total != MaxIdentities {
		t.Fatalf("setup: store holds %d entries, %d banned, want %d of each",
			total, banned, MaxIdentities)
	}

	// A genuinely misbehaving peer now arrives and misbehaves its way up.
	// The store being full must slow this down at most, never prevent it.
	newcomer := identityKey(MaxIdentities)
	for j := 0; j < 5; j++ {
		ps.AdjustKey(newcomer, ScoreInvalidMessage)
	}
	if !ps.BannedKey(newcomer) {
		t.Fatal("a peer that misbehaved its way to the ban threshold was never recorded " +
			"because the store was full: identity banning is disabled for the life of " +
			"the process, for the price of filling the store once")
	}
	if _, total := bannedCount(ps); total > MaxIdentities {
		t.Fatalf("store holds %d identities, want at most %d", total, MaxIdentities)
	}
}

// TestEarnedGoodwillIsNotTheFirstThingEvicted is the other half of what
// identityWorth measures, and the half a "keep the lowest score" reading of
// this store misses entirely.
//
// A score is not only an answer to BannedKey. Up at ScoreCeiling it is earned
// headroom: how many more penalties a peer with a long good history absorbs
// before it crosses the threshold. Evicting the highest score first therefore
// does not discard something neutral — it lets an attacker halve an honest
// peer's ban budget on demand, for the price of one cheap message per
// throwaway identity.
func TestEarnedGoodwillIsNotTheFirstThingEvicted(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	honest := identityKey(0)
	for i := 0; i < ScoreCeiling; i++ {
		ps.AdjustKey(honest, ScoreUsefulMessage)
	}

	// A flood of free identities, each scoring once, filling the store twice
	// over.
	for i := 1; i <= MaxIdentities*2; i++ {
		ps.AdjustKey(identityKey(i), ScoreUsefulMessage)
	}

	// The honest peer now has a bad run. With its goodwill intact that takes
	// (ScoreCeiling - ScoreBanThreshold) / 20 = 10 invalid messages; with the
	// goodwill discarded it takes 5.
	penalties := 0
	for !ps.BannedKey(honest) && penalties < 100 {
		ps.AdjustKey(honest, ScoreInvalidMessage)
		penalties++
	}
	want := (ScoreCeiling - ScoreBanThreshold) / -ScoreInvalidMessage
	if penalties < want {
		t.Fatalf("an honest peer holding %d points of earned goodwill was banned after %d "+
			"invalid messages, want %d: the flood evicted its balance and halved its budget",
			ScoreCeiling, penalties, want)
	}
}

// TestIdentityStoreStillRecordsAWorseNewcomer guards the other side of the
// retention rule: protecting what is worth keeping must not turn into
// refusing to learn. An identity that misbehaves its way to the threshold is
// recorded even against a store already full of entries no reader consults.
func TestIdentityStoreStillRecordsAWorseNewcomer(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxIdentities; i++ {
		ps.AdjustKey(identityKey(i), ScoreUsefulMessage)
	}
	newcomer := identityKey(MaxIdentities)
	ps.AdjustKey(newcomer, ScoreProtocolViolation)
	ps.AdjustKey(newcomer, ScoreProtocolViolation)
	if !ps.BannedKey(newcomer) {
		t.Fatal("an identity that misbehaved its way to the ban threshold was not recorded " +
			"while the store was full of entries no reader consults")
	}
	if _, total := bannedCount(ps); total > MaxIdentities {
		t.Fatalf("store holds %d identities, want at most %d", total, MaxIdentities)
	}
}

// TestAPeerPastTheFirstTierOutlivesACheaperFlood pins the property that
// actually holds about escalation, replacing one that did not.
//
// The claim this replaces was that the staleness tie-break lets an escalating
// peer beat a flood of one-shot identities at its own worth tier, because it
// is the one still sending. It is the freshest only until the next arrival,
// and one flood arrival between the target's messages — one TLS handshake
// apiece — keeps a peer at -20 out of the store indefinitely. That limit is
// inherent: a bounded store and free identities cannot both hold, so a
// sustained flood can always displace an entry that has not yet distinguished
// itself from a one-shot.
//
// What the ordering decides is how far the flood reaches, and this is the
// line it cannot cross. One more penalty than the flood carries puts a peer
// out of reach for good, because worth, not recency, is what separates the
// tiers. The previous ordering — lowest score first — had no such line:
// escalating made a peer the *preferred* victim, so the same flood evicted it
// at every tier. That contrast is the reason this ordering is shaped the way
// it is, and it is what this test would lose if the ordering were changed
// back.
func TestAPeerPastTheFirstTierOutlivesACheaperFlood(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	// Two penalties: worth 40, against a flood that arrives carrying 20.
	target := identityKey(1 << 40)
	ps.AdjustKey(target, ScoreInvalidMessage)
	ps.AdjustKey(target, ScoreInvalidMessage)

	for i := 1; i <= MaxIdentities*3; i++ {
		ps.AdjustKey(identityKey(i), ScoreInvalidMessage)
	}

	ps.identityMu.Lock()
	e, present := ps.identity[string(target)]
	ps.identityMu.Unlock()
	if !present {
		t.Fatalf("a peer carrying two penalties was evicted by %d one-penalty arrivals: "+
			"the flood reaches past the first tier, so escalating a peer to a ban can be "+
			"prevented at every step rather than only at the first",
			MaxIdentities*3)
	}
	if e.score != 2*ScoreInvalidMessage {
		t.Fatalf("target score is %d, want %d — it was evicted and re-admitted, which resets "+
			"the escalation the flood is supposed to be unable to touch",
			e.score, 2*ScoreInvalidMessage)
	}
}
