package spec_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"zycord/spec"
)

// TestNoEmbeddedParameterFileRepeatsAnObjectMember refuses a duplicate JSON
// object key anywhere in a shipped parameter file.
//
// It exists because nothing else in this package can see one. RFC 8259 says
// object member names SHOULD be unique but does not require it, and Go's
// encoding/json silently keeps the LAST member of a repeated name — so a
// parameter file with the same key twice parses, produces the same
// *params.Params, the same ConsensusRoot, the same genesis id and the same
// golden vectors as the file without the repeat. Every pin in this package
// stays green. The one thing that moves is blake3 over the file's raw bytes,
// which is the value a release announces (spec.Hash, MainnetParamsHash) — and
// the announced-hash literal in vector_test.go moves with the duplicate baked
// in, so it ratifies the mistake instead of catching it. That is exactly how a
// copy-pasted `notes` member reached the announced mainnet parameter hash once.
//
// The stakes are not only ours. spec/ is the compatibility contract rather
// than documentation about it, so these bytes are what a second implementation
// reads: a strict parser (serde_json with a duplicate-key guard, Python's
// object_pairs_hook, most JSON-Schema validators in strict mode) may reject
// the file outright or resolve the repeat the other way, which is a peer that
// cannot start or a peer that disagrees. A duplicate key is therefore a defect
// to catch before a freeze, not a cosmetic one to fix after — after genesis
// the repair costs a re-announcement of the hash.
func TestNoEmbeddedParameterFileRepeatsAnObjectMember(t *testing.T) {
	for _, name := range spec.Networks() {
		raw, err := spec.RawFor(name)
		if err != nil {
			t.Fatalf("RawFor(%q): %v", name, err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.UseNumber()
		if err := rejectDuplicateKeys(dec, "$"); err != nil {
			t.Errorf("the %s parameter file is not strict JSON: %v\n"+
				"Go keeps the last member and every consensus pin in this package "+
				"stays green, but the announced parameter hash is taken over these "+
				"raw bytes and a strict decoder in another implementation may refuse "+
				"them. Delete the repeat and re-derive the hash before it freezes.",
				name, err)
		}
	}
}

// rejectDuplicateKeys walks one JSON value from dec, failing on the first
// object that names a member twice. It reads tokens rather than decoding into
// a map precisely because a map is where the evidence is lost.
func rejectDuplicateKeys(dec *json.Decoder, path string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil // a scalar: nothing to check, and dec has consumed it
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return fmt.Errorf("%s: object member name is not a string", path)
			}
			if seen[key] {
				return fmt.Errorf("%s repeats object member %q", path, key)
			}
			seen[key] = true
			if err := rejectDuplicateKeys(dec, path+"."+key); err != nil {
				return err
			}
		}
	case '[':
		for i := 0; dec.More(); i++ {
			if err := rejectDuplicateKeys(dec, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	// Consume the matching closing delimiter.
	if _, err := dec.Token(); err != nil {
		return err
	}
	return nil
}
