package chain_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"zycord/core/types"
	"zycord/node/storage"
	"zycord/wallet"
)

// The reopening guard for the payload-plant defect: bytes shaped like a
// completed transaction, placed inside a crashed record's own payload by
// whoever authored the block, making recovery permanently unavailable. See
// docs/RUNNING.md's recovery section for the full account.
//
// It was closed at storage format version 4 by escaping recordMagic out of
// every payload the store writes, and the decision was recorded in the framing
// the measurement earned: that is PRICING and not impossibility. The escape
// does not cover the record's own 32-byte header, whose record-checksum field
// is forceable to the magic by CRC32 affinity, and a candidate anchored there
// reads its own more and length fields out of the first few dozen bytes of the
// payload that follows.
//
// What makes that unpayable is one property of THIS package, and nothing in
// node/storage can defend it:
//
//	NO DURABLE WRITE BEGINS A PAYLOAD WITH ATTACKER-CHOSEN BYTES.
//
// Every durable key here is a fixed two-byte prefix followed by a hash-derived
// run or a structural counter, and every value that starts early enough to be
// in reach is itself a hash or a counter. So the bytes a candidate must read
// cannot be authored — they can only be ground for, offline, at a cost the 96
// bytes an ISSUE certificate lets a signer choose freely do not reduce, because
// those land at payload offset 75 and are escaped besides.
//
// The day a feature needs an attacker-chosen key at the start of a payload,
// that grind collapses and the payload-plant defect reopens on its own terms.
// This file is the thing that says so out loud instead of letting it be
// discovered. If it fails, the fix is not to widen the guard: it is to reopen
// the defect and take the named upgrade path — the per-store salt recorded in
// storage.escapePayload's doc.

// guardPayloadReach is how far into a payload the guard treats as reachable by
// a candidate anchored inside the record's own header.
//
// Derived rather than picked, and deliberately larger than the derivation, in
// the shape rule 27 asks for. The magic can be forced at recordCRCOff (28), and
// the deepest place it can start while still overlapping the header at all is
// offset 31, from which the candidate's own 32 header bytes end at 63 — payload
// byte 31. The scoping memo written for the escape quotes 34 for the same span.
// The guard uses 40 so that the verdict does not turn on which of those two
// numbers is exact: asserting over the range costs nothing and is the only form
// that survives either of them being off.
const guardPayloadReach = 40

// durableKeyPrefixes is the closed set of key families node/chain writes,
// registered here so that a family this fixture has never seen fails loudly
// instead of passing unexamined.
//
// It is the enumeration the escape decision rests on. Every one of these is a
// fixed prefix followed by an address, a hash, a big-endian height, or a fixed
// literal — see cellKey, addrKey, hashKey, heightKey and the meta constants in
// store.go.
var durableKeyPrefixes = map[string]string{
	"c/": "cell: prefix + 32-byte address + 32-byte word, both hash-derived",
	"s/": "spent: prefix + 32-byte address",
	"n/": "seen: prefix + 32-byte certificate id",
	"h/": "header: prefix + 32-byte block id",
	"b/": "block: prefix + 32-byte block id",
	"i/": "index: prefix + big-endian height",
	"u/": "undo: prefix + 32-byte block id",
	"m/": "meta: a fixed literal key",
}

// TestNoDurableWriteBeginsAPayloadWithAttackerChosenBytes is the payload-plant
// defect's reopening trigger, armed.
//
// The fixture drives a real chain through a real certificate whose free fields
// a remote party chooses — ISSUE's SymbolHash and Minter are 32 unconstrained
// bytes each, which is the carrier — and then reads the durable store back
// and asks, of every key and value it holds, whether the attacker's bytes ever
// land inside the first guardPayloadReach bytes of the record that carries
// them.
//
// The instrument reports a positive state rather than silence (rule 26): the
// marker MUST be found in durable data, at a payload offset past the reach. A
// run where the marker never reached the store at all would prove nothing and
// is a failure, not a pass.
func TestNoDurableWriteBeginsAPayloadWithAttackerChosenBytes(t *testing.T) {
	// 32 bytes of the attacker's choosing. High-entropy and fixed, so a
	// coincidental four-byte match against a hash-derived key would be a
	// deterministic failure this fixture could be re-rolled out of, rather
	// than a flake.
	var marker [32]byte
	for i := range marker {
		marker[i] = byte(0xD5 ^ (i * 37))
	}

	p := devnetEasy()
	dir := t.TempDir()
	issuer := key(t, 1)
	minter := key(t, 2)
	n := openNode(t, dir, p, issuer.Persistent())
	n.mine(t, int(p.CoinbaseMaturity)+2)

	var symbol types.Hash
	copy(symbol[:], marker[:])
	b := &wallet.Builder{
		Params: p,
		Program: wallet.Issue(issuer.Persistent(), drops(1_000_000), 8, symbol,
			minter.PubKey()),
		TTL:     n.chain.Height() + 5,
		Deposit: wallet.SelfDeposit(issuer.Persistent(), issuer.Persistent()),
		FeeBid:  wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(10)),
		Signers: []*wallet.Key{issuer},
	}
	cert, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := n.pool.Add(cert, n.chain.Snapshot().State, n.chain.Height()); err != nil {
		t.Fatalf("the pool refused the certificate this fixture is built on: %v", err)
	}

	// A RETIRE as well, purely so the spent registry is exercised: without one
	// the "s/" family never reaches the store and the census below would be
	// asserting over seven of eight families while claiming eight.
	retire := &wallet.Builder{
		Params:  p,
		Program: wallet.Retire(issuer.OneShot()),
		Seq:     1,
		TTL:     n.chain.Height() + 5,
		Deposit: wallet.SelfDeposit(issuer.Persistent(), issuer.Persistent()),
		FeeBid:  wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(10)),
		Signers: []*wallet.Key{issuer},
	}
	retireCert, err := retire.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := n.pool.Add(retireCert, n.chain.Snapshot().State, n.chain.Height()); err != nil {
		t.Fatalf("the pool refused the retire certificate: %v", err)
	}

	n.mine(t, 2)
	n.close(t)

	// The census is taken from the store rather than from the source, because
	// what has to hold is a property of the bytes on disk and not of a call
	// site somebody remembered to look at.
	s, err := storage.Open(dir, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	keyOffsetInPayload := calibrateKeyOffset(t, marker[:])

	seen := map[string]int{}
	var markerDepths []int
	var total int
	err = s.ScanPrefix(nil, func(k, v []byte) error {
		total++
		if len(k) < 2 {
			return fmt.Errorf("a durable key is %d byte(s) long (%q); every family in this "+
				"package is a two-byte prefix plus a body", len(k), k)
		}
		prefix := string(k[:2])
		if _, ok := durableKeyPrefixes[prefix]; !ok {
			return fmt.Errorf("NO DURABLE WRITE BEGINS A PAYLOAD WITH ATTACKER-CHOSEN BYTES "+
				"is no longer defended: key family %q is not in durableKeyPrefixes, so nothing "+
				"here has checked what its first bytes are made of (key %x)", prefix, k)
		}
		seen[prefix]++

		// The record payload this mutation would produce if it were the first
		// in its batch — which any of them can be, since writeState iterates
		// Go maps and the order is randomised per run.
		payload := payloadPrefixFor(k, v, keyOffsetInPayload)
		reach := payload
		if len(reach) > guardPayloadReach {
			reach = reach[:guardPayloadReach]
		}
		if at := indexAnyWindow(reach, marker[:]); at >= 0 {
			return fmt.Errorf("THE PAYLOAD-PLANT DEFECT IS REOPENED BY ITS OWN TERMS: a durable write begins its "+
				"payload with attacker-chosen bytes.\n"+
				"  key    %x\n"+
				"  bytes the attacker chose appear at payload offset %d, inside the %d the "+
				"header carrier can read.\n"+
				"The escape in node/storage prices that defect at an offline preimage grind ONLY "+
				"because the bytes a forged candidate must read are hash-derived. They are "+
				"not any more, so the grind collapses. Do not widen this guard: reopen the defect "+
				"and take the per-store salt recorded in storage.escapePayload's doc.",
				k, at, guardPayloadReach)
		}
		if at := indexAnyWindow(payload, marker[:]); at >= 0 {
			markerDepths = append(markerDepths, at)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Positive state, so an "all clear" here is a measurement and not an
	// absence of output.
	if total == 0 {
		t.Fatal("the store holds no durable keys at all, so the census above examined nothing")
	}
	if len(markerDepths) == 0 {
		t.Fatal("the attacker's bytes never reached durable storage, so this run measured a " +
			"fixture that does not exercise the property. The certificate is supposed to " +
			"put 32 chosen bytes into a cell value and into the stored block body.")
	}
	sort.Ints(markerDepths)
	if markerDepths[0] <= guardPayloadReach {
		t.Fatalf("the shallowest attacker-chosen byte sits at payload offset %d, which is "+
			"inside the %d a header-anchored candidate reads",
			markerDepths[0], guardPayloadReach)
	}

	// Coverage: a family the fixture never produced is a family this guard did
	// not check, and saying so is worth more than a green run that quietly
	// covered five of eight.
	var missing []string
	for prefix := range durableKeyPrefixes {
		if seen[prefix] == 0 {
			missing = append(missing, prefix)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("the fixture produced no durable key in these families: %v. They are declared "+
			"in durableKeyPrefixes and therefore claimed to be checked; either drive them or "+
			"take them out of the registry, but do not leave the guard asserting over a "+
			"subset it does not name", missing)
	}

	// The detector's own direction, asserted rather than assumed (rule 22).
	// Every row above came back clean; a detector that cannot come back dirty
	// would produce exactly the same output. This is the write the guard exists
	// to catch — a key whose body is chosen by the party who supplied it — put
	// through the same arithmetic the census used.
	attackerKey := append([]byte("x/"), marker[:]...)
	probe := payloadPrefixFor(attackerKey, []byte("value"), keyOffsetInPayload)
	if len(probe) > guardPayloadReach {
		probe = probe[:guardPayloadReach]
	}
	if at := indexAnyWindow(probe, marker[:]); at < 0 {
		t.Fatal("the detector does not fire on a key made entirely of the attacker's bytes, " +
			"so every clean row above is a clean row from an instrument that cannot report " +
			"anything else")
	}

	t.Logf("guard held over %d durable keys across %d families; the attacker's 32 chosen bytes "+
		"reached durable storage %d time(s), shallowest at payload offset %d against a reach "+
		"of %d; the detector fires on a synthetic attacker-chosen key",
		total, len(seen), len(markerDepths), markerDepths[0], guardPayloadReach)
}

// calibrateKeyOffset measures where a mutation's key starts inside the record
// payload the storage layer actually writes, instead of restating the batch
// encoding here.
//
// A second spelling of that arithmetic is a mirror that answers a question the
// writer was never asked (rule 24): if the encoding grows a field, a hard-coded
// 5 keeps this guard reading the wrong bytes and reporting all clear. The
// probe below reads it off the log of a store with exactly one record in it,
// where the payload begins immediately after the record header.
func calibrateKeyOffset(t *testing.T, probeKey []byte) int {
	t.Helper()
	dir := t.TempDir()
	s, err := storage.Open(dir, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	b := &storage.Batch{}
	b.Put(probeKey, []byte("probe-value"))
	if err := s.Commit(b); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "log"))
	if err != nil {
		t.Fatal(err)
	}
	at := bytes.Index(raw, probeKey)
	if at < 0 {
		t.Fatal("the probe key is not in the log verbatim, so the payload layout cannot be " +
			"read off it and this guard would be measuring the wrong offsets")
	}
	// The log holds one record: header, then payload. Everything before the
	// key inside that payload is what a mutation costs ahead of its key.
	off := at - recordHeaderLenForTest
	if off < 0 {
		t.Fatalf("the probe key starts at log offset %d, inside the record header; the "+
			"calibration below would be nonsense", at)
	}
	return off
}

// recordHeaderLenForTest mirrors node/storage's record header length. It is a
// constant of the on-disk format rather than of this package, so the guard
// above checks it: if the header grows, the calibration lands inside the
// payload and calibrateKeyOffset reports an offset the census would notice as
// a shifted marker depth rather than passing quietly.
const recordHeaderLenForTest = 32

// payloadPrefixFor rebuilds the head of the record payload one mutation would
// produce if it were written first: whatever the encoding puts ahead of the
// key, then the key, then whatever it puts between the key and the value, then
// the value.
//
// keyOffset is measured, not assumed. The gap between the key and the value is
// the value's own length prefix, and the guard only needs an UPPER bound on
// how deep the value starts — a smaller gap would make this stricter, never
// looser, so four is written here rather than measured a second time.
func payloadPrefixFor(k, v []byte, keyOffset int) []byte {
	out := make([]byte, 0, keyOffset+len(k)+4+len(v))
	out = append(out, make([]byte, keyOffset)...)
	out = append(out, k...)
	out = append(out, make([]byte, 4)...)
	return append(out, v...)
}

// indexAnyWindow reports the first offset in haystack at which any four-byte
// window of needle appears, or -1.
//
// Four bytes because that is the smallest run an attacker has to place to move
// one of a candidate's fields, and because a whole-needle match would miss the
// case that matters: a key that carried a slice of the attacker's bytes rather
// than all of them.
func indexAnyWindow(haystack, needle []byte) int {
	best := -1
	for i := 0; i+4 <= len(needle); i++ {
		if at := bytes.Index(haystack, needle[i:i+4]); at >= 0 && (best < 0 || at < best) {
			best = at
		}
	}
	return best
}
