// Package update is the release-update mechanism: the signed manifest a node
// checks, the keys it checks it against, and the machinery that replaces a
// binary once the check has passed.
//
// Two properties shape every file in here.
//
// **It is standard library only.** `make check-imports` pins that, for the
// same reason it pins core/ and node/: this package decides whether to execute
// code it just downloaded, and the argument for trusting it is that there is
// very little of it to read. It also has to compile into the desktop wallet,
// which is a separate module, and every dependency added here is a new hash in
// that module's go.sum.
//
// **It is not the protocol.** Nothing in this package enters a consensus
// preimage, and nothing in core/ or node/ may import it. An update key is
// release policy about the binary, in the sense node/checkpoints uses the
// phrase — client release policy, edited on a schedule the network never sees.
package update

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// keysJSON is update/keys.json, embedded for the reason spec/checkpoints.json
// is embedded: which keys a binary will accept is a property of that binary,
// checkable by whoever holds it, and not something a file beside it can change.
//
// A key set cannot be delivered over the channel the keys protect. Whatever is
// compiled in here is the whole of what this build can ever be handed a release
// through, which is why an unused key costs nothing and a missing one cannot be
// added afterwards.
//
//go:embed keys.json
var keysJSON []byte

// KeyRole is what a key is for. There are exactly two.
type KeyRole string

const (
	// RoleCurrent signs manifests today. Its private half is the one held by
	// the release pipeline.
	RoleCurrent KeyRole = "current"
	// RoleNext signs nothing yet, and exists so that a rotation is an ordinary
	// update rather than a fleet-wide hand-download.
	//
	// Its private half is deliberately NOT in the release pipeline. A key that
	// is compromised with `current` is not a spare, and the whole value of this
	// role is that the compromise of whatever holds `current` does not reach it.
	RoleNext KeyRole = "next"
)

// Key is one entry of the embedded set.
type Key struct {
	ID   string  `json:"id"`
	Role KeyRole `json:"role"`
	Key  string  `json:"key"`
}

// KeySet is the parsed contents of keys.json.
type KeySet struct {
	Schema    int    `json:"schema"`
	Algorithm string `json:"algorithm"`
	Keys      []Key  `json:"keys"`
}

// keysSchema is the only layout this build can read. It is checked rather than
// assumed so that a future format is a refusal with a reason instead of a
// silent misread of fields that happen to parse.
const keysSchema = 1

// keysAlgorithm is the only signature algorithm this build can verify. There is
// no negotiation and no second implementation: a set naming anything else is
// refused rather than partially honoured.
const keysAlgorithm = "ed25519"

var (
	// embedded is the parsed key set, or the failure that stopped it parsing.
	// Both are computed once, at init, because the alternative is a package
	// that looks fine until the first update check and fails there.
	embedded    KeySet
	embeddedErr error

	// verifiers is the embedded set as ed25519 keys, in the order keys.json
	// lists them, so a signature is tried against `current` first.
	verifiers []ed25519.PublicKey
)

func init() {
	embedded, embeddedErr = ParseKeys(keysJSON)
	if embeddedErr != nil {
		return
	}
	verifiers = make([]ed25519.PublicKey, 0, len(embedded.Keys))
	for _, k := range embedded.Keys {
		raw, _ := hex.DecodeString(k.Key) // validated by ParseKeys
		verifiers = append(verifiers, ed25519.PublicKey(raw))
	}
}

// ParseKeys decodes and validates a key set.
//
// It is strict about everything it can be strict about, because the input is
// a file this build ships rather than anything a stranger sends: a malformed
// set here is a mistake made by whoever edited it, and the only useful moment
// to find that out is the build's own test run.
func ParseKeys(raw []byte) (KeySet, error) {
	var ks KeySet
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Unknown fields are refused rather than ignored. keys.json holds keys and
	// nothing else on purpose — no comment, no generation date, no path — and
	// a decoder that skipped what it did not recognise would let all three back
	// in without a test noticing.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ks); err != nil {
		return KeySet{}, fmt.Errorf("update: keys.json does not parse: %w", err)
	}
	if ks.Schema != keysSchema {
		return KeySet{}, fmt.Errorf("update: keys.json is schema %d, and this build reads schema %d", ks.Schema, keysSchema)
	}
	if ks.Algorithm != keysAlgorithm {
		return KeySet{}, fmt.Errorf("update: keys.json names algorithm %q, and this build verifies %q only", ks.Algorithm, keysAlgorithm)
	}
	if len(ks.Keys) == 0 {
		return KeySet{}, errors.New("update: keys.json carries no keys, so this build could never accept a release")
	}

	seenID := map[string]bool{}
	seenKey := map[string]bool{}
	current := 0
	next := 0
	for i, k := range ks.Keys {
		switch k.Role {
		case RoleCurrent:
			current++
		case RoleNext:
			next++
		default:
			return KeySet{}, fmt.Errorf("update: keys.json entry %d has role %q, which is neither %q nor %q", i, k.Role, RoleCurrent, RoleNext)
		}
		if k.ID == "" {
			return KeySet{}, fmt.Errorf("update: keys.json entry %d has no id", i)
		}
		if seenID[k.ID] {
			return KeySet{}, fmt.Errorf("update: keys.json names id %q twice, so a message naming it names two keys", k.ID)
		}
		seenID[k.ID] = true

		if len(k.Key) != hex.EncodedLen(ed25519.PublicKeySize) {
			return KeySet{}, fmt.Errorf("update: key %q is %d hex characters; an ed25519 public key is %d", k.ID, len(k.Key), hex.EncodedLen(ed25519.PublicKeySize))
		}
		if k.Key != strings.ToLower(k.Key) {
			return KeySet{}, fmt.Errorf("update: key %q is not lower-case hex; one spelling per key, so a comparison against an announcement cannot fail on case", k.ID)
		}
		decoded, err := hex.DecodeString(k.Key)
		if err != nil {
			return KeySet{}, fmt.Errorf("update: key %q is not hex: %w", k.ID, err)
		}
		if allZero(decoded) {
			return KeySet{}, fmt.Errorf("update: key %q is all zero, which is a placeholder somebody forgot to replace rather than a key", k.ID)
		}
		if seenKey[k.Key] {
			return KeySet{}, fmt.Errorf("update: key %q repeats a key already in the set; a spare that equals the key it is spare for is not a spare", k.ID)
		}
		seenKey[k.Key] = true
	}
	if current != 1 {
		return KeySet{}, fmt.Errorf("update: keys.json has %d keys with role %q, and exactly one signs", current, RoleCurrent)
	}
	if next > 1 {
		return KeySet{}, fmt.Errorf("update: keys.json has %d keys with role %q, and at most one may be held back", next, RoleNext)
	}
	return ks, nil
}

// Keys returns a copy of the embedded key set, or the error that stopped it
// parsing.
//
// The copy is deep, and it has to be. A KeySet returned by value still shares
// the backing array of its Keys slice, so a caller holding one could rewrite the
// very key bytes ParseManifest verifies signatures against — from anywhere in
// the program, with no error, and with no symptom until a forged manifest
// verified or a real one did not.
func Keys() (KeySet, error) {
	if embeddedErr != nil {
		return KeySet{}, embeddedErr
	}
	out := embedded
	out.Keys = make([]Key, len(embedded.Keys))
	copy(out.Keys, embedded.Keys)
	return out, nil
}

// Verifiers returns the public keys a manifest signature may verify against,
// `current` first.
//
// A signature is accepted if ANY of them verifies it. That is what makes a
// rotation an ordinary update: a manifest signed by the incoming key is
// already acceptable to every binary that shipped with it held back.
func Verifiers() []ed25519.PublicKey {
	// Deep, for the reason Keys gives. An ed25519.PublicKey is a []byte, so
	// copying the outer slice copies HEADERS: the elements still point at the
	// package's own key bytes, and `vs[0][0] ^= 0xff` reaches straight through
	// a copy that looks like one.
	out := make([]ed25519.PublicKey, len(verifiers))
	for i, v := range verifiers {
		out[i] = append(ed25519.PublicKey(nil), v...)
	}
	return out
}

// KeyByID returns the entry with this id.
func (ks KeySet) KeyByID(id string) (Key, bool) {
	for _, k := range ks.Keys {
		if k.ID == id {
			return k, true
		}
	}
	return Key{}, false
}

// KeyByRole returns the entry holding this role.
func (ks KeySet) KeyByRole(r KeyRole) (Key, bool) {
	for _, k := range ks.Keys {
		if k.Role == r {
			return k, true
		}
	}
	return Key{}, false
}

// KeysHash is SHA-256 over the raw embedded file, so an operator can confirm
// which key set a binary carries.
//
// **It is sha256 rather than the tagged blake3 every other digest in this tree
// uses, and that is the point of it.** spec.CheckpointsHash answers "what did
// this build compile in", to a reader who already has the build. This answers
// "is the key set in my binary the one the announcement names", to a reader
// comparing against a signed statement they were handed — and the only way that
// comparison is worth anything is if they can compute both sides themselves:
//
//	sha256sum update/keys.json
//
// A domain-separated blake3 would need this binary to check this binary, which
// is not a check. Nothing here enters a preimage, so there is no tag to collide
// with and no reason to reach for one.
func KeysHash() [sha256.Size]byte { return sha256.Sum256(keysJSON) }

// KeysJSON returns the raw bytes of the embedded file.
func KeysJSON() []byte { return append([]byte(nil), keysJSON...) }

// allZero reports whether every byte is zero, which is what an unreplaced
// placeholder looks like and what a real key never does.
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
