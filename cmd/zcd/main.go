// Command zcd is the Zycord command-line tool.
//
// At M0 it does the things that can be done without a node: rebuild genesis,
// print the frozen parameters, make keys, and check an implementation against
// the golden vectors. The node (zycordd) arrives at M1.
//
// The command that matters most here is `zcd genesis`. A launch announcement
// commits, weeks in advance, to the code tag, the parameter hash, the genesis
// id and the launch height — and this rebuilds all four in milliseconds, from
// source, on any machine. There is nothing else to trust.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"zycord/core/crypto"
	"zycord/core/fold"
	"zycord/core/genesis"
	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/pow/randomx"
	"zycord/spec"
	"zycord/wallet"
)

// version is stamped by the build. An unstamped binary says so rather than
// claiming a release it is not.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "genesis":
		err = cmdGenesis(os.Args[2:])
	case "params":
		err = cmdParams(os.Args[2:])
	case "key":
		err = cmdKey(os.Args[2:])
	case "wallet":
		err = cmdWallet(os.Args[2:])
	case "ui":
		err = cmdUI(os.Args[2:])
	case "emission":
		err = cmdEmission(os.Args[2:])
	case "vectors":
		err = cmdVectors(os.Args[2:])
	case "version":
		cmdVersion(os.Stdout)
	case "help", "-h", "--help":
		usage()
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "zcd:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `zcd — the Zycord command-line tool

  zcd genesis  [--testnet | --devnet | --params FILE]
                                            rebuild block 0 and print its id
  zcd params   [--testnet | --devnet | --params FILE]
                                            print the frozen parameters
  zcd key new  [--one-shot]                 print a key and its addresses
  zcd wallet new    --out KEYFILE           create an encrypted key file
  zcd wallet address --key KEYFILE          show an address
  zcd wallet balance --key KEYFILE          ask a node for a balance
  zcd wallet send    --key KEYFILE --to ADDR --amount N
  zcd wallet sweep   --key KEYFILE --to ADDR --one-shot
  zcd wallet retire  --key KEYFILE [--addr ADDR]
  zcd ui       --key KEYFILE                open the wallet in a browser
  zcd emission --height N [--testnet | --devnet]
                                            print the coinbase at a height
  zcd vectors  [--dir spec/vectors]         check this build against the vectors
  zcd version

There is no coin yet. Genesis has not happened. Anyone selling you ZCD today
is scamming you.
`)
}

// cmdVersion prints the version and, under it, the proof-of-work engine THIS
// BINARY carries.
//
// The second line is the one that had nowhere to be printed. RandomX is
// compiled only under the `randomx` build tag; `spec/params.json` and
// `spec/params.testnet.json` both declare `pow_engine: randomx-v1`; so a build
// without the tag refuses to start on mainnet and on the public testnet, and
// only `--devnet` runs. Until this line existed the only way to find that out
// was to try it — `zcd params` prints what the NETWORK requires, which is a
// different question with the same answer written in it, and reading the first
// as an answer to the second is exactly the confusion that let a release
// pipeline ship six platforms of binaries nobody could join a network with.
//
// The first line keeps its exact shape, `zcd <version>`. `packaging/install.sh`
// runs this command as the last thing it does and the Homebrew formula asserts
// on it; the engine goes underneath rather than into it, so a parser of the
// first line is unaffected and a human reading install.sh's output is told.
func cmdVersion(w io.Writer) {
	fmt.Fprintln(w, "zcd", version)
	if randomx.Available() {
		fmt.Fprintf(w, "proof of work: %s — this binary can join mainnet and the public testnet\n", randomx.Name)
		fmt.Fprintln(w, "  It is a cgo build, so it is NOT byte-identical across machines and is")
		fmt.Fprintln(w, "  not covered by SHA256SUMS.binaries. See docs/INSTALL.md, \"Two tiers\".")
		return
	}
	fmt.Fprintf(w, "proof of work: %s only — built without the randomx build tag\n", pow.Dev{}.Name())
	fmt.Fprintf(w, "  This binary refuses to start on any network whose pow_engine is %s,\n", randomx.Name)
	fmt.Fprintln(w, "  which is both mainnet and the public testnet. Only --devnet runs here.")
	fmt.Fprintln(w, "  For a binary that joins those, take a -randomx archive from the release")
	fmt.Fprintln(w, "  page or run `make build-randomx`. See docs/INSTALL.md, \"Two tiers\".")
}

// network resolves which parameter set a command should use from the network
// flags, and is the one place the exclusivity rule lives.
//
// It returns the embedded NAME rather than the parsed set, because two things
// need it: the parameters themselves, and the raw bytes `zcd genesis` hashes to
// print the params hash. Those two must never disagree — a params hash computed
// over one file and a genesis id built from another is a launch announcement
// that commits to nothing.
func network(path string, devnet, testnet bool) (string, error) {
	chosen := 0
	for _, on := range []bool{path != "", devnet, testnet} {
		if on {
			chosen++
		}
	}
	if chosen > 1 {
		return "", errors.New("--params, --testnet and --devnet are mutually exclusive")
	}
	switch {
	case path != "":
		return "", nil
	case testnet:
		return "testnet", nil
	case devnet:
		return "devnet", nil
	}
	return "mainnet", nil
}

// loadParams resolves the parameter set a command should use: an explicit file,
// or one of the embedded sets (mainnet by default).
func loadParams(fs *flag.FlagSet, path string, devnet, testnet bool) (*params.Params, error) {
	name, err := network(path, devnet, testnet)
	if err != nil {
		return nil, err
	}
	if name == "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return params.Parse(raw)
	}
	raw, err := spec.RawFor(name)
	if err != nil {
		return nil, err
	}
	return params.Parse(raw)
}

func addNetworkFlags(fs *flag.FlagSet) (*string, *bool, *bool) {
	path := fs.String("params", "", "path to a parameter file (defaults to the embedded mainnet set)")
	devnet := fs.Bool("devnet", false, "use the embedded devnet parameters")
	// The public testnet is selected by name, not by handing the binary a file. A
	// file path is a set of parameters the operator supplies, so what network a
	// node joined was a property of that operator's disk; with the set embedded
	// and pinned by a genesis vector, --testnet makes it a property of the
	// binary, and the announced params hash recomputable from the binary alone.
	testnet := fs.Bool("testnet", false, "use the embedded public testnet parameters")
	return path, devnet, testnet
}

func cmdGenesis(args []string) error {
	fs := flag.NewFlagSet("genesis", flag.ExitOnError)
	path, devnet, testnet := addNetworkFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := loadParams(fs, *path, *devnet, *testnet)
	if err != nil {
		return err
	}

	block, state, err := genesis.Build(p)
	if err != nil {
		return err
	}

	// The bytes the params hash is taken over, resolved by the same rule that
	// chose the parameters above rather than by a second ladder that can drift
	// from it.
	name, err := network(*path, *devnet, *testnet)
	if err != nil {
		return err
	}
	var raw []byte
	if name == "" {
		raw, err = os.ReadFile(*path)
	} else {
		raw, err = spec.RawFor(name)
	}
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "network\t%s\n", p.Name)
	fmt.Fprintf(w, "chain id\t%d\n", p.ChainID)
	fmt.Fprintf(w, "params hash\t%s\n", hexOf(spec.Hash(raw)))
	fmt.Fprintf(w, "genesis id\t%s\n", hexOf(block.Header.ID()))
	fmt.Fprintf(w, "state root\t%s\n", hexOf(block.Header.StateRoot))
	fmt.Fprintf(w, "genesis time\t%d\n", p.GenesisTime)
	fmt.Fprintf(w, "cells written\t%d\n", len(state.SortedCells()))
	fmt.Fprintf(w, "allocations\t0\n")
	return w.Flush()
}

func cmdParams(args []string) error {
	fs := flag.NewFlagSet("params", flag.ExitOnError)
	path, devnet, testnet := addNetworkFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := loadParams(fs, *path, *devnet, *testnet)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "network\t%s (chain id %d)\n", p.Name, p.ChainID)
	fmt.Fprintf(w, "proof of work\t%s (re-keyed every %d blocks, %d-block lag)\n",
		p.PoWEngine, p.RandomXKeyInterval, p.RandomXKeyLag)
	fmt.Fprintf(w, "block time\t%d s\n", p.TargetBlockSeconds)
	fmt.Fprintf(w, "epoch\t%d blocks\n", p.EpochLength)
	fmt.Fprintf(w, "certificate TTL\t%d blocks maximum\n", p.TTLMax)
	// The sequential target T is consensus state (whitepaper §8.1), not a
	// params constant, so this command — which has no chain to read from —
	// prints its genesis value and the rule that moves it, not a "current"
	// ceiling. `zcd genesis` and a running node's own params RPC are where a
	// live T is observable.
	t0 := p.SeqGasTargetGenesis
	fmt.Fprintf(w, "sequential target (genesis)\t%d (floor: never falls below this)\n", t0)
	fmt.Fprintf(w, "sequential ceiling (genesis)\t%d (2T; burst bound %d = 4T)\n", p.SeqGasLimit(t0), p.SeqGasBurst(t0))
	fmt.Fprintf(w, "parallel ceiling (genesis)\t%d (%dx the sequential ceiling)\n", p.ParGasLimit(t0), p.ParGasRatio)
	fmt.Fprintf(w, "block ceiling (genesis)\t%d certificates, %d bytes\n", p.MaxCertsPerBlock(t0), p.BlockByteLimit(t0))
	fmt.Fprintf(w, "certificate list capacity\t%d (static; the structural bound the ceiling above scales toward)\n", p.CertListCapacity)
	fmt.Fprintf(w, "block byte capacity\t%d (static; a block must stay small enough to send in one message)\n", p.BlockByteCapacity)
	fmt.Fprintf(w, "ceiling growth/decay\t+1/%d per epoch of full blocks, -1/%d per epoch idle\n", p.CeilingGrowthDivisor, p.CeilingDecayDivisor)
	fmt.Fprintf(w, "health gate\t%d bps of cited competing headers per epoch, above which growth withholds\n", p.HealthGateBps)
	fmt.Fprintf(w, "skip fee\t%s drops (constant)\n", p.SkipFee.String())
	fmt.Fprintf(w, "emission at genesis\t%s drops/block\n", p.GenesisEmission.String())
	fmt.Fprintf(w, "tail emission\t%s drops/block\n", p.TailEmission.String())
	fmt.Fprintf(w, "treasury share\t%d bps of every subsidy (never of fees)\n", p.TreasuryShareBps)
	fmt.Fprintf(w, "coinbase maturity\t%d blocks\n", p.CoinbaseMaturity)
	fmt.Fprintf(w, "undo horizon\t%d blocks\n", p.UndoDepth)
	fmt.Fprintf(w, "phase 1 (bonds)\theight %d\n", p.H1Bond)
	fmt.Fprintf(w, "phase 1 (cEVM)\theight %d\n", p.H1VM)
	fmt.Fprintf(w, "phase 2 (stake)\theight %d\n", p.H2PoS)
	return w.Flush()
}

func cmdKey(args []string) error {
	if len(args) == 0 || args[0] != "new" {
		return errors.New("usage: zcd key new [--one-shot]")
	}
	fs := flag.NewFlagSet("key new", flag.ExitOnError)
	oneShot := fs.Bool("one-shot", false, "show the one-shot address as the primary one")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "seed\t%s\n", hex.EncodeToString(k.Seed()))
	if *oneShot {
		fmt.Fprintf(w, "one-shot address\t%s\n", hexBytes(addrOf(k, crypto.AddrVersionOneShot)))
		fmt.Fprintf(w, "persistent address\t%s\n", hexBytes(addrOf(k, crypto.AddrVersionPersistent)))
	} else {
		fmt.Fprintf(w, "persistent address\t%s\n", hexBytes(addrOf(k, crypto.AddrVersionPersistent)))
		fmt.Fprintf(w, "one-shot address\t%s\n", hexBytes(addrOf(k, crypto.AddrVersionOneShot)))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr,
		"\nThe seed is the key. Anyone who reads it owns everything the addresses hold.\n"+
			"One-shot addresses burn themselves when first debited; persistent ones do not.")
	return nil
}

func cmdEmission(args []string) error {
	fs := flag.NewFlagSet("emission", flag.ExitOnError)
	height := fs.Uint64("height", 0, "block height")
	path, devnet, testnet := addNetworkFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	p, err := loadParams(fs, *path, *devnet, *testnet)
	if err != nil {
		return err
	}
	e := p.Emission(*height)
	whole, frac := e.Div64(100_000_000)
	fmt.Printf("height %d (epoch %d): %s drops = %s.%08d ZCD\n",
		*height, p.Epoch(*height), e.String(), whole.String(), frac)

	// The split, printed from the same arithmetic the fold performs, so that
	// reading it here and reading F11 cannot disagree.
	treasury := e.MulDiv64(p.TreasuryShareBps, 10000)
	producer, _ := e.Sub(treasury)
	fmt.Printf("  producer   %s drops (%d bps)\n", producer.String(), 10000-p.TreasuryShareBps)
	fmt.Printf("  treasury   %s drops (%d bps)\n", treasury.String(), p.TreasuryShareBps)

	if e.Eq(p.TailEmission) && *height > 0 {
		fmt.Println("this is the perpetual tail")
	}
	return nil
}

func cmdVectors(args []string) error {
	fs := flag.NewFlagSet("vectors", flag.ExitOnError)
	dir := fs.String("dir", "spec/vectors", "directory holding the golden vectors")
	if err := fs.Parse(args); err != nil {
		return err
	}

	vectors, err := spec.LoadVectors(*dir)
	if err != nil {
		return err
	}
	// "0 passed, 0 failed" is not a pass. A conformance command that exits 0
	// having replayed nothing certifies a build on the strength of a mistyped
	// --dir, which is the shape of instrument this repository keeps catching
	// itself building (CONTRIBUTING).
	if len(vectors) == 0 {
		return fmt.Errorf("no vectors in %s: nothing was checked", *dir)
	}
	var passed, failed int
	for _, v := range vectors {
		if err := runVector(v); err != nil {
			failed++
			fmt.Printf("FAIL  %-32s %v\n", v.Name, err)
			continue
		}
		passed++
		fmt.Printf("ok    %s\n", v.Name)
	}
	fmt.Printf("\n%d passed, %d failed\n", passed, failed)
	if failed > 0 {
		return fmt.Errorf("%d vectors failed: this build does not implement the protocol", failed)
	}
	return nil
}

func runVector(v *spec.Vector) error {
	p, err := spec.ParamsFor(v.Params)
	if err != nil {
		return err
	}
	s, err := v.Pre.BuildState()
	if err != nil {
		return err
	}
	b, err := v.DecodeBlock(p)
	if err != nil {
		return fmt.Errorf("the block does not decode: %w", err)
	}

	res, applyErr := fold.ApplyBlock(s, b, p)
	if !v.Expect.Valid {
		// The same five conditions spec/vector_test.go applies, deliberately: this
		// command is the conformance harness a build ships, and a harness weaker
		// than the suite would certify a build the suite rejects. Four of the five
		// were missing in the first version of this harness — only "an error came
		// back" was checked — so a build that rejected the block by the wrong rule,
		// or with the wrong error, or that mutated state on the way out, passed here
		// while failing `go test ./spec`.
		//
		// The rule-is-present check is not redundant with the comparison after
		// it. Without it, a corpus entry carrying no rule and a build whose
		// fold names none compare "" against "" and agree — which is the
		// arrangement a build with a rule deleted and a corpus regenerated
		// against it produces, and the one case where agreement means neither
		// side is saying anything.
		if applyErr == nil {
			return errors.New("the block was accepted; the vector says it is invalid")
		}
		if !errors.Is(applyErr, fold.ErrInvalidBlock) {
			return fmt.Errorf("got %v, want an invalid-block error", applyErr)
		}
		if v.Expect.Rule == "" {
			return errors.New("the vector names no rule; it predates the requirement " +
				"that every invalid vector pin the rule that rejects it, or it was " +
				"generated by a fold that rejected the block without naming one")
		}
		if got := fold.Rule(applyErr); got != v.Expect.Rule {
			return fmt.Errorf("rejected by %q, the vector pins %q (%v)", got, v.Expect.Rule, applyErr)
		}
		if got := spec.Snapshot(s); !got.Equal(v.Expect.Post) {
			return errors.New("a rejected block changed the state")
		}
		return nil
	}
	if applyErr != nil {
		return applyErr
	}
	if len(res.Outcomes) != len(v.Expect.Outcomes) {
		return fmt.Errorf("got %d outcomes, want %d", len(res.Outcomes), len(v.Expect.Outcomes))
	}
	for i, want := range v.Expect.Outcomes {
		if got := res.Outcomes[i]; got.Outcome.String() != want.Outcome {
			return fmt.Errorf("outcome %d: %s, want %s", i, got.Outcome, want.Outcome)
		}
	}
	if got := spec.Snapshot(s); !got.Equal(v.Expect.Post) {
		return errors.New("the post-state differs from the vector")
	}
	return nil
}

func addrOf(k *wallet.Key, version byte) []byte {
	a := k.Address(version)
	return a[:]
}

func hexOf(h crypto.Hash) string { return "0x" + hex.EncodeToString(h[:]) }

func hexBytes(b []byte) string { return "0x" + hex.EncodeToString(b) }
