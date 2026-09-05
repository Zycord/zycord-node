package params

import (
	"encoding/binary"
	"fmt"
	"reflect"

	"zycord/core/crypto"
	"zycord/core/u256"
)

// consensusTag marks a field as excluded from the consensus root. Everything
// with a json tag is consensus unless it says otherwise, so the failure mode of
// forgetting the tag is a parameter that is *over*-committed — noisy, not
// silent.
const consensusTag = "consensus"

// ConsensusRoot is a digest over every consensus parameter.
//
// It exists so that two nodes which disagree about any parameter derive
// different genesis ids, and therefore refuse to talk to each other (R3-1).
// Without it, two nodes could agree on the genesis block, gossip happily, and
// then diverge at the first evaluation of whichever rule they disagreed about —
// a silent fork whose trigger is a configuration file. Parameter divergence has
// to be a connection refusal, not a latent split.
//
// The walk is reflective on purpose. A hand-written preimage would need somebody
// to remember to extend it, and a forgotten field here is exactly the
// silent-fork vector this function exists to close. The same walk enforces the
// positivity invariant, so both jobs fail together or not at all.
//
// The encoding is length-prefixed field by field, so no two parameter sets can
// collide by shifting bytes between a name and a value, and a renamed or
// retyped field changes the root even if its value does not.
//
// This is recomputed once per certificate on the block-verification path, and
// it is tempting to memoise it into a field here. Resist that, or argue it
// properly first. The sharp objection is not staleness under copying —
// it is that a memoised field has to be populated by somebody, and forgetting
// is silent: a Params built by struct literal would carry a zero root, nodes
// that all forgot would agree with each other and fork away from everyone who
// did not, and nothing anywhere would report an error. That is a silent fork
// arriving through a performance optimisation, in the function that exists to
// make parameter divergence a connection refusal. Any memoisation has to make
// "not yet computed" impossible to observe, not merely unlikely.
//
// Whether it is even worth the argument is a measured question, not a felt
// one: node/verify's BenchmarkConsensusRoot and
// TestConsensusRootStaysCheapRelativeToOneSignature pin this walk's cost as a
// fraction of one strict Ed25519 verification on the same path, and the test
// fails if that fraction stops being small.
func (p *Params) ConsensusRoot() crypto.Hash {
	var payload []byte
	for _, f := range consensusFields(p) {
		payload = appendLenPrefixed(payload, []byte(f.name))
		payload = append(payload, f.kind)
		payload = appendLenPrefixed(payload, f.value)
	}
	return crypto.Sum(crypto.TagConsensusRoot, payload)
}

// Type discriminators, so that a field which changes type changes the root.
const (
	kindUint64 byte = 1
	kindInt    byte = 2
	kindU256   byte = 3
	kindString byte = 4
)

type consensusField struct {
	name  string
	kind  byte
	value []byte
}

// consensusFields returns the committed parameters in declaration order, which
// is the canonical order: it is visible in the struct, reviewable in a diff, and
// cannot drift from what a reader sees.
func consensusFields(p *Params) []consensusField {
	v := reflect.ValueOf(p).Elem()
	t := v.Type()

	out := make([]consensusField, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := f.Tag.Get("json")
		if name == "" || !f.IsExported() {
			continue
		}
		if idx := indexByte(name, ','); idx >= 0 {
			name = name[:idx]
		}
		if f.Tag.Get(consensusTag) == "-" {
			continue
		}

		var cf consensusField
		cf.name = name
		switch val := v.Field(i).Interface().(type) {
		case uint64:
			cf.kind, cf.value = kindUint64, le64(val)
		case int:
			cf.kind, cf.value = kindInt, le64(uint64(val))
		case u256.U256:
			b := val.Bytes()
			cf.kind, cf.value = kindU256, b[:]
		case string:
			cf.kind, cf.value = kindString, []byte(val)
		default:
			// A consensus parameter of an unhandled type would be silently
			// uncommitted, which is the failure this function exists to
			// prevent. Refuse to produce a root at all.
			panic(fmt.Sprintf(
				"params: %s has type %T, which ConsensusRoot does not know how to commit to; "+
					"add it to the switch or mark the field consensus:\"-\"", name, val))
		}
		out = append(out, cf)
	}
	return out
}

// ConsensusFieldNames lists the parameters committed to by ConsensusRoot. It
// exists for the test that pins the consensus/non-consensus boundary, so that
// moving a field across it is a visible change rather than an accident.
func (p *Params) ConsensusFieldNames() []string {
	fields := consensusFields(p)
	names := make([]string, len(fields))
	for i, f := range fields {
		names[i] = f.name
	}
	return names
}

func appendLenPrefixed(dst, b []byte) []byte {
	return append(append(dst, le64(uint64(len(b)))...), b...)
}

func le64(v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return b[:]
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
