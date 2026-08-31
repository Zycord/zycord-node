package update_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"zycord/update"
)

// TestTheEmbeddedKeySetParses is the test that has to pass before any of the
// others mean anything.
//
// The set is parsed once at init and the failure is remembered rather than
// panicked, so a malformed keys.json produces a package that compiles, links,
// ships, and refuses every release at the first check on a user's machine. This
// is where that gets caught instead.
func TestTheEmbeddedKeySetParses(t *testing.T) {
	ks, err := update.Keys()
	if err != nil {
		t.Fatalf("the embedded keys.json does not parse: %v", err)
	}
	if len(ks.Keys) == 0 {
		t.Fatal("the embedded key set is empty, so this build could never accept a release")
	}
}

// TestExactlyOneCurrentKeyAndAtMostOneNext pins the shape a rotation depends on.
//
// One `current`, because two would mean two private halves that can sign a
// release and no way to say which one did. At most one `next`, because the
// promotion rule in the manifest verifier names a single incoming key: a set
// with two spares would leave "which spare superseded it" undecidable at the
// exact moment nobody can afford to guess.
func TestExactlyOneCurrentKeyAndAtMostOneNext(t *testing.T) {
	ks, err := update.Keys()
	if err != nil {
		t.Fatal(err)
	}
	current, next := 0, 0
	for _, k := range ks.Keys {
		switch k.Role {
		case update.RoleCurrent:
			current++
		case update.RoleNext:
			next++
		default:
			t.Errorf("key %q has role %q, which is neither current nor next", k.ID, k.Role)
		}
	}
	if current != 1 {
		t.Errorf("the set has %d current keys; exactly one signs", current)
	}
	if next > 1 {
		t.Errorf("the set has %d next keys; at most one may be held back", next)
	}
}

// TestTheSpareIsNotTheKeyItIsSpareFor is the invariant with the sharpest
// failure mode, so it gets its own test.
//
// `next` exists so that whatever compromises `current` does not reach it. A set
// where the two are equal still parses, still verifies every real release, and
// still looks correct in every output this package produces — and buys nothing
// at all on the one day it was supposed to matter.
func TestTheSpareIsNotTheKeyItIsSpareFor(t *testing.T) {
	ks, err := update.Keys()
	if err != nil {
		t.Fatal(err)
	}
	cur, ok := ks.KeyByRole(update.RoleCurrent)
	if !ok {
		t.Fatal("no current key")
	}
	next, ok := ks.KeyByRole(update.RoleNext)
	if !ok {
		t.Skip("this set holds no spare, which is allowed")
	}
	if cur.Key == next.Key {
		t.Error("the next key equals the current key, so the rotation path protects nothing")
	}
	if cur.ID == next.ID {
		t.Errorf("both keys are called %q", cur.ID)
	}
}

// TestEveryKeyIsAUsableEd25519PublicKey checks the encoding rules one at a
// time, because each of them is a different way to ship a set that parses and
// cannot verify anything.
func TestEveryKeyIsAUsableEd25519PublicKey(t *testing.T) {
	ks, err := update.Keys()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range ks.Keys {
		if got, want := len(k.Key), hex.EncodedLen(ed25519.PublicKeySize); got != want {
			t.Errorf("key %q is %d hex characters, want %d", k.ID, got, want)
			continue
		}
		if k.Key != strings.ToLower(k.Key) {
			t.Errorf("key %q is not lower-case hex; an operator comparing it against an "+
				"announcement should not have to think about case", k.ID)
		}
		raw, err := hex.DecodeString(k.Key)
		if err != nil {
			t.Errorf("key %q is not hex: %v", k.ID, err)
			continue
		}
		zero := true
		for _, b := range raw {
			if b != 0 {
				zero = false
				break
			}
		}
		if zero {
			t.Errorf("key %q is all zero, which is a placeholder nobody replaced", k.ID)
		}
	}
}

// TestVerifiersAreOrderedCurrentFirst pins the order a signature is tried in.
//
// Both keys are accepted, so order changes no outcome — it changes cost. Every
// release but the one that rotates is signed by `current`, so trying the spare
// first would run an extra verification on every check every node ever makes,
// to be right on the one release where it matters and wrong on all the rest.
func TestVerifiersAreOrderedCurrentFirst(t *testing.T) {
	ks, err := update.Keys()
	if err != nil {
		t.Fatal(err)
	}
	vs := update.Verifiers()
	if len(vs) != len(ks.Keys) {
		t.Fatalf("Verifiers returned %d keys, the set holds %d", len(vs), len(ks.Keys))
	}
	cur, ok := ks.KeyByRole(update.RoleCurrent)
	if !ok {
		t.Fatal("no current key")
	}
	if got := hex.EncodeToString(vs[0]); got != cur.Key {
		t.Errorf("the first verifier is %s, want the current key %s", got, cur.Key)
	}
}

// TestVerifiersIsACopy guards a mutable package-level slice handed to callers.
//
// The set is process-global and read on every check. A caller that appends to
// or reorders the returned slice would be editing what every later check
// verifies against, from anywhere in the program, with no error and no symptom
// until a real release failed to install.
func TestVerifiersIsACopy(t *testing.T) {
	first := update.Verifiers()
	if len(first) == 0 {
		t.Fatal("no verifiers")
	}
	original := hex.EncodeToString(first[0])
	for i := range first {
		first[i] = make(ed25519.PublicKey, ed25519.PublicKeySize)
	}
	second := update.Verifiers()
	if got := hex.EncodeToString(second[0]); got != original {
		t.Errorf("mutating the returned slice changed the package's own keys: now %s, was %s", got, original)
	}
}

// TestKeysHashIsWhatSha256sumPrints is the whole reason KeysHash is sha256 and
// not the tagged blake3 the rest of this tree uses.
//
// The value exists to be compared against a signed announcement by somebody who
// has the file and a shell. If it could only be computed by the binary whose
// key set is in question, the comparison would be the binary checking itself.
func TestKeysHashIsWhatSha256sumPrints(t *testing.T) {
	raw, err := os.ReadFile("keys.json")
	if err != nil {
		t.Fatal(err)
	}
	if want, got := sha256.Sum256(raw), update.KeysHash(); want != got {
		t.Errorf("KeysHash() = %x, sha256sum of keys.json = %x", got, want)
	}
	if got, want := string(update.KeysJSON()), string(raw); got != want {
		t.Error("KeysJSON() does not return the bytes on disk, so the hash covers something a reader cannot see")
	}
}

// TestKeysJSONIsACopy is the same argument as TestVerifiersIsACopy, for the
// bytes the hash is taken over.
func TestKeysJSONIsACopy(t *testing.T) {
	first := update.KeysJSON()
	if len(first) == 0 {
		t.Fatal("empty")
	}
	original := first[0]
	first[0] = original + 1
	if update.KeysJSON()[0] != original {
		t.Error("mutating the returned bytes changed the embedded file")
	}
}

// TestKeysJSONCarriesNothingButKeys is the anonymity rule, enforced by the
// parser rather than by a reviewer's memory.
//
// keys.json holds keys and nothing else on purpose. A bare 32-byte key names
// nobody and resolves to nothing, which is what makes it safe to commit — but a
// `comment`, a generation date, a path or a hostname beside it would not be,
// and those are exactly the fields somebody adds while being helpful. The
// decoder refuses unknown fields, so adding one turns this test red instead of
// shipping a longitude in a file nobody re-reads.
func TestKeysJSONCarriesNothingButKeys(t *testing.T) {
	for _, extra := range []string{
		`{"schema":1,"algorithm":"ed25519","comment":"generated on the build box","keys":[{"id":"zu1","role":"current","key":"2bb4ba8a60ebfd018761b2347b14c37c17716b432837fdc066a27a63d131f6bd"}]}`,
		`{"schema":1,"algorithm":"ed25519","generated_at":"2026-09-01T10:00:00Z","keys":[{"id":"zu1","role":"current","key":"2bb4ba8a60ebfd018761b2347b14c37c17716b432837fdc066a27a63d131f6bd"}]}`,
		`{"schema":1,"algorithm":"ed25519","keys":[{"id":"zu1","role":"current","key":"2bb4ba8a60ebfd018761b2347b14c37c17716b432837fdc066a27a63d131f6bd","note":"laptop"}]}`,
	} {
		if _, err := update.ParseKeys([]byte(extra)); err == nil {
			t.Errorf("a key set carrying an extra field was accepted:\n  %s", extra)
		}
	}
}

// TestAMalformedKeySetIsRefusedWithAReason walks the failures one at a time.
//
// Every case here is a set that json.Unmarshal alone would accept. The point of
// ParseKeys is that none of them reaches a user as "no update available".
func TestAMalformedKeySetIsRefusedWithAReason(t *testing.T) {
	const good = "2bb4ba8a60ebfd018761b2347b14c37c17716b432837fdc066a27a63d131f6bd"
	const other = "0a45e0ec71f973456f02a9b4df98c29d11f5dfeeffb5a14f3c4de78637f2051f"
	for _, tc := range []struct{ name, raw string }{
		{"a schema this build cannot read",
			`{"schema":2,"algorithm":"ed25519","keys":[{"id":"zu1","role":"current","key":"` + good + `"}]}`},
		{"an algorithm this build cannot verify",
			`{"schema":1,"algorithm":"ml-dsa-65","keys":[{"id":"zu1","role":"current","key":"` + good + `"}]}`},
		{"no keys at all",
			`{"schema":1,"algorithm":"ed25519","keys":[]}`},
		{"no current key",
			`{"schema":1,"algorithm":"ed25519","keys":[{"id":"zu2","role":"next","key":"` + good + `"}]}`},
		{"two current keys",
			`{"schema":1,"algorithm":"ed25519","keys":[{"id":"zu1","role":"current","key":"` + good + `"},{"id":"zu2","role":"current","key":"` + other + `"}]}`},
		{"two spares",
			`{"schema":1,"algorithm":"ed25519","keys":[{"id":"zu1","role":"current","key":"` + good + `"},{"id":"zu2","role":"next","key":"` + other + `"},{"id":"zu3","role":"next","key":"` + strings.Repeat("ab", 32) + `"}]}`},
		{"a repeated id",
			`{"schema":1,"algorithm":"ed25519","keys":[{"id":"zu1","role":"current","key":"` + good + `"},{"id":"zu1","role":"next","key":"` + other + `"}]}`},
		{"a spare equal to the key it is spare for",
			`{"schema":1,"algorithm":"ed25519","keys":[{"id":"zu1","role":"current","key":"` + good + `"},{"id":"zu2","role":"next","key":"` + good + `"}]}`},
		{"a role that is neither",
			`{"schema":1,"algorithm":"ed25519","keys":[{"id":"zu1","role":"retired","key":"` + good + `"}]}`},
		{"an all-zero placeholder",
			`{"schema":1,"algorithm":"ed25519","keys":[{"id":"zu1","role":"current","key":"` + strings.Repeat("00", 32) + `"}]}`},
		{"upper-case hex",
			`{"schema":1,"algorithm":"ed25519","keys":[{"id":"zu1","role":"current","key":"` + strings.ToUpper(good) + `"}]}`},
		{"a key of the wrong length",
			`{"schema":1,"algorithm":"ed25519","keys":[{"id":"zu1","role":"current","key":"` + good[:60] + `"}]}`},
		{"a key that is not hex",
			`{"schema":1,"algorithm":"ed25519","keys":[{"id":"zu1","role":"current","key":"` + strings.Repeat("zz", 32) + `"}]}`},
		{"a key with no id",
			`{"schema":1,"algorithm":"ed25519","keys":[{"id":"","role":"current","key":"` + good + `"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := update.ParseKeys([]byte(tc.raw)); err == nil {
				t.Errorf("accepted %s", tc.name)
			}
		})
	}
}
