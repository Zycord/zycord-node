package params_test

import (
	"reflect"
	"sort"
	"testing"

	"zycord/core/genesis"
	"zycord/core/params"
	"zycord/core/u256"
	"zycord/spec"
)

// TestEveryConsensusParameterChangesTheGenesisID is R3-1.
//
// Two nodes that agree on the genesis block but disagree about any consensus
// parameter would gossip happily and then diverge at the first evaluation of
// whichever rule they disagreed about — a silent fork whose trigger is a
// configuration file. This walks every parameter, changes it, and requires the
// genesis id to move.
//
// A forgotten field here is precisely that silent-fork vector, so the test is
// reflective rather than a list: a parameter added later is covered without
// anybody remembering to cover it.
func TestEveryConsensusParameterChangesTheGenesisID(t *testing.T) {
	base := spec.Mainnet()
	baseRoot := base.ConsensusRoot()
	baseID, err := genesis.NetworkID(base)
	if err != nil {
		t.Fatal(err)
	}

	v := reflect.ValueOf(base).Elem()
	typ := v.Type()
	checked := 0

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name := field.Tag.Get("json")
		if name == "" || !field.IsExported() || field.Tag.Get("consensus") == "-" {
			continue
		}

		// Perturb by one, in whichever direction keeps the value legal — every
		// numeric parameter must stay positive, so a value of one moves up.
		var bumped reflect.Value
		switch cur := v.Field(i).Interface().(type) {
		case uint64:
			bumped = reflect.ValueOf(cur + 1)
		case int:
			bumped = reflect.ValueOf(cur + 1)
		case u256.U256:
			bumped = reflect.ValueOf(cur.SatAdd(u256.One))
		case string:
			bumped = reflect.ValueOf(cur + "-x")
		default:
			t.Fatalf("%s has type %T, which this test cannot perturb; "+
				"ConsensusRoot should have refused to build a root for it", name, cur)
		}

		t.Run(name, func(t *testing.T) {
			mutated := *spec.Mainnet()
			reflect.ValueOf(&mutated).Elem().Field(i).Set(bumped)

			if mutated.ConsensusRoot() == baseRoot {
				t.Fatalf("changing %s did not change the consensus root; two nodes "+
					"differing in it would share a network id and fork silently", name)
			}
			// H1VM/H2PoS ordering and similar invariants can make a perturbed
			// set unbuildable; the root check above is the load-bearing one.
			if id, err := genesis.NetworkID(&mutated); err == nil && id == baseID {
				t.Fatalf("changing %s did not change the genesis id", name)
			}
		})
		checked++
	}

	if checked < 25 {
		t.Fatalf("the walk covered only %d parameters; it is broken", checked)
	}
}

// TestBlock0CommitsToTheConsensusRoot pins the identity the signature
// preimage rests on: block 0 carries the consensus root as its ParentID, so
// the root is not merely correlated with the genesis id — it is *inside* it.
//
// Why the preimage needs it stated here. V2 binds the consensus root and not
// the genesis id, because core/genesis imports core/fold, which imports
// core/validity, so a genesis id is not reachable from a V-rule; and because a
// rule that is stateless by design should not need a state root folded to
// answer. What makes that exact rather than merely convenient is this identity
// together with TestEveryConsensusParameterChangesTheGenesisID above: the root
// is committed inside the id, and every parameter moves both — so there is no
// pair of parameter sets one of them separates and the other does not.
//
// What kills a mutation here, and what that does and does not make this
// assertion. core/fold's B10 refuses a genesis block whose ParentID is not this
// node's consensus root, and genesis.Build folds the block it makes, so
// replacing ParentID alone fails at the Build call above with B10 named in the
// error rather than at the comparison — measured.
//
// That makes the comparison a SECOND statement of the identity. It does not
// make it dead code, and the two are different claims that one mutant cannot
// separate. Deleting B10's own ParentID clause as well leaves this comparison
// as the thing that fails, at this line and naming the ParentID — also
// measured. So the guard is doubled rather than duplicated, which is the point
// of writing it here: this is where the signature preimage's argument depends
// on the identity, and it now holds even if the fold's clause is lost.
func TestBlock0CommitsToTheConsensusRoot(t *testing.T) {
	for _, name := range spec.Networks() {
		raw, err := spec.RawFor(name)
		if err != nil {
			t.Fatal(err)
		}
		p, err := params.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		b, _, err := genesis.Build(p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if b.Header.ParentID != p.ConsensusRoot() {
			t.Fatalf("%s: block 0's ParentID is not the consensus root, so binding the root "+
				"in the signing message is no longer binding what the genesis id commits to", name)
		}
	}
}

// TestConsensusBoundaryIsExplicit pins which parameters are consensus and which
// are not. Moving a field across the boundary must be a visible change in this
// test, never a side effect of adding a struct tag.
func TestConsensusBoundaryIsExplicit(t *testing.T) {
	p := spec.Mainnet()

	committed := map[string]bool{}
	for _, n := range p.ConsensusFieldNames() {
		committed[n] = true
	}

	// Every json-tagged field is consensus unless explicitly excluded, so the
	// exclusion list is the thing worth stating.
	wantExcluded := []string{"notes"}

	v := reflect.ValueOf(p).Elem()
	typ := v.Type()
	var excluded []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := f.Tag.Get("json")
		if name == "" || !f.IsExported() {
			continue
		}
		if idx := len(name); idx > 0 {
			if c := indexComma(name); c >= 0 {
				name = name[:c]
			}
		}
		if !committed[name] {
			excluded = append(excluded, name)
		}
	}
	sort.Strings(excluded)
	sort.Strings(wantExcluded)

	if !reflect.DeepEqual(excluded, wantExcluded) {
		t.Fatalf("the consensus boundary moved: excluded = %v, want %v.\n"+
			"Adding a parameter to the excluded set means nodes may disagree "+
			"about it and still share a network id.", excluded, wantExcluded)
	}
}

// TestNotesDoNotAffectConsensus: prose about the parameters is not a parameter.
// It changes the params hash, which covers the file, and must not change the
// genesis id, which covers the values.
func TestNotesDoNotAffectConsensus(t *testing.T) {
	a := spec.Mainnet()
	b := spec.Mainnet()
	b.Notes = map[string]string{"anything": "at all"}

	if a.ConsensusRoot() != b.ConsensusRoot() {
		t.Fatal("editing a note changed the consensus root")
	}
	idA, err := genesis.NetworkID(a)
	if err != nil {
		t.Fatal(err)
	}
	idB, err := genesis.NetworkID(b)
	if err != nil {
		t.Fatal(err)
	}
	if idA != idB {
		t.Fatal("editing a note changed the genesis id")
	}
}

// TestNetworksAreStructurallySeparate: devnet and mainnet must not merely be
// unlikely to mix, they must be unable to (M1-G8).
func TestNetworksAreStructurallySeparate(t *testing.T) {
	mainnet, err := genesis.NetworkID(spec.Mainnet())
	if err != nil {
		t.Fatal(err)
	}
	devnet, err := genesis.NetworkID(spec.Devnet())
	if err != nil {
		t.Fatal(err)
	}
	if mainnet == devnet {
		t.Fatal("mainnet and devnet share a network id")
	}
}

// TestConsensusRootIsStable: the root is a pure function of the values, so two
// loads of the same file agree and a reordering of the JSON does not matter.
func TestConsensusRootIsStable(t *testing.T) {
	if spec.Mainnet().ConsensusRoot() != spec.Mainnet().ConsensusRoot() {
		t.Fatal("the consensus root is not deterministic")
	}
	reordered, err := params.Parse(reorderJSON(spec.MainnetJSON()))
	if err != nil {
		t.Fatal(err)
	}
	if reordered.ConsensusRoot() != spec.Mainnet().ConsensusRoot() {
		t.Fatal("the consensus root depends on the order of keys in the file")
	}
}

func indexComma(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			return i
		}
	}
	return -1
}
