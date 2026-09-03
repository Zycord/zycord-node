# Deferred backlog

**This is the only place to look.** Every finding raised against this tree is
either landed or recorded below; nothing is parked anywhere else, and there is no
tracker to consult alongside it. Items that are the owner's alone to discharge —
anything that has to be announced, deployed or measured rather than written — are
marked as such where they sit.

An entry here outlives whatever raised it, because what it records is a residual
and the condition that reopens it, not a ticket — the chain-reset procedure and
the class epics themselves are the cases to expect.

This file is the map of everything currently parked as deferred, written into the
repository so that it survives publication as files alone, with no history and no
tracker alongside it. Every entry is self-contained on purpose: the reasoning is
here, not somewhere it can be looked up.

**How to read it.** Each entry states, in one line each: *what* the defect or
decision is, *why it was deferred*, and *what reopens it* — the concrete
condition under which it stops being deferrable. Where one entry depends on
another it names it by its subject rather than by a number, so the dependency is
followable inside this file.

Entries are grouped by class, because the class decides *when* each one is
handled. Every item sits in exactly one group.

---

## 1. Release-event queue — moves the announced parameter hash

**Each entry here edits a file whose whole bytes are hashed into that network's
announced parameter hash, so any one edit is a release event on the affected
network.** `notes` is `consensus:"-"`, so a reworded note moves the published
hash while every consensus value stays put — which is exactly why the hashes are
written down as literals in `spec/vector_test.go` rather than recomputed. The
test fails with the new value printed, and updating it is the moment somebody
decides the commitment has moved.

**This group is empty.**

What decides whether an edit lands here is whether the network's hash has been
announced yet:

- **Mainnet is `pre-genesis`.** Its parameters are what the pre-genesis freeze
  exists to fix, `spec/chain-ids.json` pins no genesis for id 1, and nothing has
  been published. An edit to `spec/params.json` before the freeze is an ordinary
  diff: regenerate the vectors, re-pin the literal, done. It stops being one the
  day the freeze flips that entry to `live` with an announced genesis id.
- **The testnet is `live`.** Its parameter hash and genesis id are pinned in the
  ledger and derived by every node at startup, so an edit to
  `spec/params.testnet.json` — prose included — is a release event from now on,
  and regenerates its vectors and re-pins its genesis. It kept chain id 2 across
  the 2026-09-06 respin under `spec/chain-ids.json`'s pre-mainnet respin
  exception; that exception lapses when mainnet launches, and a respin after
  that takes the next free id.
- **Devnet is `ephemeral`** and pins nothing, by design.

An entry belongs here the next time a note or a value inside `spec/params*.json`
is found wrong on a network whose hash is out; the group exists so that such
edits are batched into one release event rather than announced one sentence at a
time.

## 2. Pre-launch hygiene — instruments that lie, guards not armed

Test instruments, coverage sweeps, harnesses, and operator-facing diagnostics
that misreport, measure nothing, or are held by no test. Worth fixing before a
public testnet is stood up as a measuring instrument; none of them blocks a
launch, because none changes shipped behaviour.

- **The public testnet has exactly one bootstrap seed, and it is ours.**
  `cmd/zycordd` ships `testnet.zycord.com:9421` so that a newcomer can start a
  downloaded binary without first copying an address out of an announcement.
  [RELEASE.md](RELEASE.md) §4 requires bootstrap nodes to be community-operable
  and to be nothing traceable to the author, and one project-run seed satisfies
  neither. *Deferred:* the alternative is a testnet nobody can join on the first
  day, which loses the honest newcomers the rule exists to protect; the entry is
  a DNS name so it moves without a release, `--no-seeds` refuses it, and the
  node prints the list it will dial. *Reopens:* when a second seed on
  infrastructure somebody else operates is published — that is what retires the
  §4 exception and the single point of failure in the same step. Until then the
  network's reachability is one host's uptime.

- **Differential runner drives parameter-shaped rules only at shipped values.**
  Every consensus rule written twice that compares a field against a parameter is
  exercised only at the value the shipped networks carry. *Deferred:* about the
  machinery's reach, not a live defect — no shipped network sits near any
  boundary. *Reopens:* the day a parameter is re-pinned near one of those
  boundaries, or when the sweep is next extended.
- **Wallet policy-reads matcher misses a dot-imported callable.** The pin widened
  its enumeration but not its matcher, so a `core/state` callable reached through
  a dot import reads as a bare identifier and is invisible. *Deferred:* test-only
  escape, demonstrated by a surviving mutant. *Reopens:* the day a dot import of
  `core/state` from package `wallet` is added.
- **Exclusion audit enforces markers on `continue` sites only.** A boundary drawn
  any other way (a type switch with no default, a `break`) is unowned and
  unregistered. *Deferred:* test-only; five of fourteen registered rows are
  already unenforced. *Reopens:* the day an unmarked boundary silently shrinks
  real coverage.
- **Sparse-population pin counts constructions, not propagations.** It sees where
  a `state.State` is created, never where a sparse one is passed on. *Deferred:*
  following propagation needs a whole-module type-check, heavier than the
  instrument it would extend. The limitation is now stated on the registry's own
  doc comment, with both routes it cannot see named there. *Reopens:* the day a
  holder of a propagated sparse state reads it — none exists at this head, the one measured
  holder having been deleted.
- **`repair` collapses "proven unsafe to cut" into "not proven safe to cut".**
  The prose distinguishes the two, but the verdict line and exit code do not, so
  a script or a skimming operator resyncs a probably-intact store. *Deferred:*
  the failure direction stays safe — both refuse. *Reopens:* the day an operator
  or runbook needs to tell a must-resync store from a merely-uncuttable one.
- **B6's parallel-gas ceiling can be driven only at a witness, never at a shipped
  parameter set.** The separating pair is `(L, L+2)` — `L+1` is odd and no block
  can carry it — and both halves are now driven, at two legal-but-unshipped
  witnesses on two independent axes (`par_gas_ratio`, and the wholly
  unconstrained `gas_par_per_sig`), so the `>` → `>=` mutant that used to survive
  is dead. What no test can do is reach B6 at a shipped set: B6 asks 3.84
  parallel gas per block byte at mainnet and 16 at testnet and devnet, against a
  *derived* Era-0 density ceiling of 3.0352. *Deferred:* the residual is a
  property of the parameters rather than of the instrument — B6 is inert at
  Era 0 by proof, not by sample. *Reopens:* the day `par_gas_ratio` is re-pinned
  below 2.3712, or a gas-schedule change lifts Era-0 density above what B6 asks;
  at that point B6 becomes an ordinary reachable rule and the witnesses are
  redundant rather than wrong.
- **Key-schedule boundary driven only at devnet's first crossing.** `k>1`, the
  mainnet/testnet intervals and the widest legal lag are not driven; the sweep
  measured this rather than assuming it. *Deferred:* about coverage reach, not a
  live defect. *Reopens:* the day the key interval or lag is swept.
- **`sim/refold` shares `core/validity`, so V-rule divergence cannot be
  separated.** The differential's V-rule agreement is a tautology. *Deferred:* a
  second copy of the validity predicate is a second thing to keep current — the
  cost that already bit once. *Reopens:* the day a V-rule needs a genuine
  differential rather than a necessity check.
- **The overflow-unreachability invariant is now asserted over folded state.**
  `TestOverflowSkipsAreUnreachableInEraZero` added one amount to a constant zero
  and so could not fail; it is replaced by two tests that do.
  `TestMaxCapSupplyBoundsEveryCreditBelowOverflow` mints the max cap into one
  slot and runs the fold to the 2^256−1 boundary, and
  `TestAssetSupplyEqualsMintedOverFoldedState` states the law itself —
  enumerate every balance cell of an asset after a fold, require the sum to
  equal its `minted` cell and `minted ≤ cap`. The ARCHITECTURE §9 proof sketch
  holds as corrected and now cites the invariant rather than asserting it.
  *Deferred:* the law is driven over one scripted fold (mints, transfers, an
  emptied cell, a skip, a cap-refused mint) and one max-cap boundary, not over
  an enumeration or randomisation of the reachable state space (the overflow family). *Reopens:* the day the invariant is wanted as a fuzz or
  state-space property rather than over driven folds.
- **Cert-width sweep is self-confirming.** `era0ShapeSpace`'s classification and
  its own actual-value computation come from the same enumeration, which misses a
  35%-wider certificate. *Deferred:* calibration figures, not enforced bounds; no
  block is mis-validated. *Reopens:* the day the classification needs a bound not
  derived from the search under test; the spec-note half rode the released
  `max_certs_per_block_genesis` note correction.
- **`SKIPPED_OVERFLOW` is in no vector and no test** while `spec/README.md` says
  every fold outcome is. *Deferred:* the outcome may be genuinely unreachable on a
  conserving chain — an argument, not a check. *Reopens:* the day the outcome is
  given a vector or an armed unreachability exemption (the overflow family).
- **A gossip-path `ErrLocal` refusal is not logged at all.** The node speaks about
  the same local fault through the sync driver but is silent on the gossip door.
  *Deferred:* the operator-visible outcome is delivered by the retrying sync path;
  the pricing (charge the peer nothing) is correct. *Reopens:* the day a local
  fault needs to be visible on both doors.
- **The revival drain in `waitForConvergence` is held by no test.** A bounded
  external kill inside the convergence window kills the mutant in ~90 s, but no
  unit test drives a convergence window. *Deferred:* the drain works; only its
  guard is missing. *Reopens:* the day a chaos regime injects a real external
  termination inside the window.
- **`devnetEasy` raises `max_target` to the maximum, blinding the harness to
  R4-H1.** The difficulty rule's answer and an attacker's declared target become
  the same value, so target-derivation rules hold vacuously. *Deferred:* a stated
  limit, not a discovered failure — the honest-case test runs on real devnet
  params. The limit is now written at `devnetEasy` itself and pinned by
  `TestDevnetEasyCannotSeparateAnR4H1GhostFromTheRule`, so a test built on the
  harness can no longer read as evidence about a declared target by accident.
  *Reopens:* the day a target-derivation rule must be observed on the
  multi-node harness — the second easy parameter set, keeping `max_target` above
  `genesis_target`, is still unwritten.
- **The storage mutation grid string-matches three deleted functions.** It applies
  zero mutations, runs the suite, sees it pass, and reports coverage of nothing.
  *Deferred:* test tooling only, nothing shipping reads it. *Reopens:* the day the
  grid is retargeted or given the "assert the substitution applied" guard.
- **`burstScenario` fails `params.Validate`.** The three burst-valve tests are
  pinned at a parameter set the protocol refuses. *Deferred:* the properties are
  almost certainly still true (a witness, not a subject); a validated fixture is
  already written down. *Reopens:* the day the fixture is swapped for the
  validated one, checking the three consumers' assertions do not move.
- **A peer that refuses a body during sync is never charged, and the test that
  pins it uses an impossible error shape.** `connSource.Body` marks every
  round-trip failure as transport fault, so `ScoreUnservedBody` prices
  served-but-wrong and never served-nothing. *Deferred:* charging nothing may be
  the correct call; what is wrong is that three sites claim a charge that cannot
  happen. *Reopens:* the day the primitive becomes a `LAUNCH.md` §4.3 decision
  (already past the three-item mark, counting this one and its siblings in this
  file).
- **The soak reports "wedged node" for a node whose RPC never bound.** The fate
  determination has an unconsidered third case, and the evidence that separates it
  is in a log line nothing reads. *Deferred:* a second defect, not a port-fix
  residue. *Reopens:* the day a "wedged" report against a healthy node starts a
  hunt in `node/` — read the log for a bind error first.
- **`era0ShapeSpace` reaches 66.3% of the derived ceiling and nothing asserts it
  cannot fall further.** The sweep now has a yardstick and does not use it.
  *Deferred:* not a correctness finding; the omissions are known and stated.
  *Reopens:* the day a dropped dimension narrows the sweep silently — a coverage
  floor makes losing ground visible.
- **The node announces the RPC is listening before it binds.** A bind failure
  leaves it running without one, so anything reading the first log line concludes
  the RPC is up. *Deferred:* the node keeps following the chain, so no `LAUNCH.md`
  §3 case is met — but a lying instrument costs hours elsewhere. *Reopens:* the day
  a verifier is used as a measuring instrument against its RPC (a near-duplicate
  of the low-severity `rpc listening` entry below).
- **The commit sidecar verifies on the lower counter slot.** Corrupting the
  highest slot — the exact failure the two-slot design exists to survive — yields
  VERIFIED evidence with a wrong high-water mark. *Deferred:* harmless while the
  read is one-directional and authorises no deletion. *Reopens:* any change that
  makes a sidecar read authorising — then the under-report authorises cutting a
  committed transaction.
- **Parameter-perturbation tests can no longer reuse corpus blocks.** Since the
  signing message binds the consensus root, a lifted corpus block fails V2 under
  any perturbed set; one B2-horizon differential lost its block-shape variety and
  its mainnet base. *No longer deferred:* the builder the entry asked for exists
  — `sim.Perturbation` rebuilds a catalogue of thirteen block shapes under an
  arbitrary parameter set, signing as it goes, and
  `TestBothFoldsAgreeOnEveryBlockShapeAtEveryPerturbedTTLMax` drives it at
  `ttl_max` 2 and 2^64-1 on a devnet and a mainnet base. What is **not** restored
  is the *corpus's* own shapes, which no builder reproduces; the rule that a
  frozen corpus block must never be folded under a perturbed set stands, and is
  written where the removed test's tombstone is.
- **[low] `zycordd` logs "rpc listening" before it binds.** The line is printed
  even when the bind fails. *Deferred:* `cmd/zycordd/` was another lane's live
  file. *Reopens:* handled with its earlier-recorded near-duplicate above — one fix
  covers both.
- **Nothing checks that a relative markdown link in `docs/` resolves.** This is the
  mechanism the pointer convention's answer rests on and it is currently
  aspirational. *Deferred:* a
  guard that does not exist yet, not aged prose. *Reopens:* the day the pointer
  convention needs the machine check it was promised — a `make` target run over
  all of `docs/`.
- **A compiled desktop binary was committed and merged, because the ignore list
  was one name short.** A bare `go build .` inside `desktop/` names its output
  after the *directory* — `desktop/desktop.exe` — and passes no `-trimpath`, so
  the 7 MB PE it writes embeds the absolute source path of every file it was
  built from: a local username and a home directory, in the one repository that
  must carry neither. `.gitignore` covered the two names `desktop/README.md`
  documents, both built with `-o` and with `-trimpath`, and did not cover that
  one; no text scan can see inside a binary, so nothing refused it until
  `sim/wiring.TestNothingPublishedIsOpaqueToTheTextScan` did, one merge too
  late. The file is deleted at the tip, all four names are ignored, and the
  reason is written beside them. *Deferred:* the blob stays reachable from two
  commits in **this** repository's own history. It reaches no reader —
  [RELEASE.md](RELEASE.md) §1 publishes the working tree copied *without* `.git`
  into a fresh `git init`, so a file deleted at the tip is absent from the
  published bytes, and this repository is private and has no public remote by
  the same section's rule. Rewriting the default branch to drop the object is a
  force-push that invalidates every clone and every open branch, which is an
  owner's decision and not a prose pass's. *Reopens:* the day this repository's
  own history is published, mirrored, or made public by any route — the purge
  has to happen **before** that, not after; and immediately if the file-only
  publication of §1 is ever replaced by pushing this history.

---

## 3. Genesis freeze

The record to read before the genesis / parameter freeze, plus the audit
findings whose own Gate sections argue they must be correct *before* the freeze.

**Class placement, stated rather than assumed:** six of the entries in this group
were first classed as *post-launch*, but each one's own argument is *pre-genesis*
(the shipped behaviour is correct, yet a genesis-frozen number, theorem, comment
or conformance surface would be wrong or undecided). They are placed here by that
argument; if the later class is the ratified truth, they move to group 4 or 5
by their fix nature.

- **The four genesis-irreversible F3 consequences.** The
  `seq_gas_target_genesis` floor on `T`; `seq_gas_capacity` capping `T` at 3.2×T0
  forever with a terminal `applied/target = 0.50`; the one-block citation window
  making the health gate fail permissive under the slow propagation it exists to
  detect; and two structural quantities frozen at genesis (dynamic subtree
  capacity, and `PoW.SeedEpoch` — now a decided, pinned field, recorded so it is
  not re-derived as a finding). *Deferred:* a record, not a defect — nothing is
  claimed broken and no fix is proposed. *Reopens:* the day someone finalises
  `seq_gas_target_genesis`, `seq_gas_capacity`, `health_gate_bps` or
  `epoch_length` — read first.
- **A chain too long to sync in one attempt makes every joiner accuse the
  bootstrap peer.** `syncAttemptTimeout` expiring mid-attempt surfaces as
  `ErrBodyUnavailable` against the one honest peer every new joiner talks to
  first. *Deferred:* self-recovers, nothing banned, sync reaches the right state
  root. *Reopens:* before scoring/ban thresholds are frozen — settle whether this
  path can reach a ban under any parameter set; do not fix by raising the
  constant.
- **`params.go:244` overstates the target headroom by six bits.** It claims 2^18
  headroom / 4.5 clamp steps where the real gap is 2^12 / 3, and an `engine.go`
  comment describes a closed timestamp-ratchet attack as open. *Deferred:* shipped
  behaviour is correct in both cases; only normative comments are wrong. *Reopens:*
  before `difficulty_clamp_factor` is frozen — the wrong number sits exactly where
  an editor would justify raising the clamp.
- **The egress bound covers replies only; gossip forwarding is unmetered.**
  `replyByteCeiling`'s comment claims the node's total egress is bounded when only
  the reply total is. *Deferred:* correcting the comment is one edit; metering
  forwarding is a large propagation-guarantee decision, and most amplification
  disappears if the ghost-announcement forwarding remainder is closed first —
  forwarding an announcement only from a node that holds the body. *Reopens:* the
  day the false comment is quoted as a reason not to add a bound, or when that
  remainder closes and forwarding is re-measured.
- **A duplicate-valued tag constant passes both domain-separation guards.** The
  identifier-keyed test cannot see a new name; the value-keyed test reads a
  hand-maintained slice a new tag is simply absent from. *Deferred:* no duplicate
  tag ships today, and the fix is a test-enumeration change with no production
  change. *Reopens:* before the tag set is frozen at genesis — a nineteenth tag is
  a pre-freeze act and the check meant to catch a bad one cannot.
- **The two folds share the whole gas schedule and every ceiling.** Tripling the
  per-write gas term, or doubling `SeqGasBurst` past B5's bound, leaves the
  differential and `./spec` green; the frozen corpus resolves ceilings back through
  the same shared function. *Deferred:* a coverage defect, not a soundness one —
  determinism verified clean. *Reopens:* before genesis — a second implementation
  that gets a ceiling scaling law wrong passes everything shipped and forks under
  load; name the full shared surface and pin or independently compute the resolved
  ceilings.
- **The poisoning-immunity theorem's overflow clause now names the true
  reason.** The §9 proof sketch no longer claims a single `(addr, asset)` slot
  cannot reach ~2^256 "under any cap" — `deriveMint` accepts `cap` = max — but
  that an asset's supply is bounded by `minted ≤ cap`, so no two same-asset
  balances sum past 2^256; `TestMaxCapSupplyBoundsEveryCreditBelowOverflow` runs
  the fold at that boundary. *Deferred:* what remains unwritten is the Era-1
  contingency — the two F8b properties that die the moment a program derives
  `GUARD_LE`/`EXACT` on a user balance slot, still to be recorded where F8b is
  documented. *Reopens:* before the theorem text (a conformance surface) is
  frozen, or when that Era-1 capability is added.
- **The citation work check and the citation-field exhaustiveness rule are
  consensus, and no vector binds either.** The fold cannot evaluate PoW, so no
  `(pre-state, block)` vector carries the first; the second is a negative rule
  needing a mutation check. *Deferred:* one may not be expressible as an ordinary
  vector at all; the conformance corpus does not catch either today. *Reopens:*
  before the corpus is frozen — an implementation that gets either wrong derives a
  different `T` and forks.

---

## 4. Documentation currency

Prose and normative comments that aged past the code. None of them moves a hashed
surface, and each can be corrected at any time; several are exactly the "a PR body
is not the repository" case this file exists to prevent.

- **The self-containment sweep is finished, and what it permanently exempts is
  three files.** It ran over `docs/`, the root documents and `spec/README.md`,
  then over every Go package tree: `spec/` first, because the golden vectors'
  `description` fields are what a second implementation reads; then `sim/`,
  `node/`, `core/`, and `cmd/` with `wallet/` and `desktop/`; then over the build
  and packaging surface — `.github/`, `.gitattributes`, `.gitignore`, `build/`,
  `go.mod`, `go.sum`, `LICENSE`, `packaging/` and the `Makefile`; and last over
  the two kinds of string a prose pass could not touch, the ones inside a
  compared operand and the ones a recipe prints. `swept` in
  `sim/wiring/history_reference_test.go` now reaches every tracked path in the
  tree, all of it measures zero under both guard patterns, and the record of what
  the sweep had not reached is deleted rather than left standing — which is what
  `TestTheUnsweptRemainderIsRecorded` demanded once the remainder hit zero.

  **What stays exempt, permanently: `spec/params.json`, `spec/params.testnet.json`
  and `spec/params.devnet.json`.** Their `notes` field is inside the bytes the
  announced parameter hash covers, so it is frozen at genesis and an edit there is
  a network respin rather than a documentation pass. The choice was between
  rewriting those notes into self-contained derivations before the freeze and
  accepting bare issue numbers in them permanently, and **the second was taken**:
  the freeze has happened, each note already states its derivation in full beside
  the token, and a bare number identifies nobody, so what is left is an opaque
  historical marker and nothing else. The `frozen` map in the same file records
  that decision where a future reader would otherwise read it as an oversight,
  and the guard refuses any path that appears in both lists, which is the one
  thing keeping `frozen` from growing into an exemption table.

  **Two classes no guard can see, so they are held by a reader instead.** A
  reference living in a *name* never reaches a guard that scans file contents:
  the four that existed are renamed, and the rule going forward is that an
  identifier is named for the property it holds and never for where the property
  was argued. And history-shaped prose that cites no number at all — "an earlier
  draft claimed the opposite" — is invisible to the pattern; it was rewritten
  only where it was entangled with a reference being replaced, because on its own
  it states a conclusion and the error it corrects inside the same sentence.

  **Anyone adding a new reference should not come here at all.** Every tracked
  path is guarded, so a new citation in a comment, a failure message, a workflow
  note or a vector description fails
  `TestNoDanglingHistoryReferenceIsPublished` where it is written, and the remedy
  is to move the meaning inline — name the mechanism, restate the derivation, or
  cite a section of a document that is in the tree. Widening the guard's
  complement to admit it is not one of the options. A whole new region of the
  tree is the one case the first guard cannot see, and
  `TestTheUnsweptRemainderIsRecorded` is left standing for exactly that: it
  demands the region be made self-contained and added to `swept`, or that a
  record be written saying what is left in it and why.

**One entry that used to sit here was removed rather than discharged, and the
difference is worth stating once.** It recorded that `sim/refold`'s
`producer < 0` clamp could never become structural, because no block could be
refused by B5 and so the B5 invalid vector three records name could not exist.
That was true at the superseded `seq_gas_target_genesis` of 2,000,000,
where B5 demanded 3.2 sequential gas per byte of block against a densest built
Era-0 shape of 2.8937. The target was re-pinned to 1,600,000, the demand fell
to 2.56, and 38 already-built shapes clear it: `core/fold` built a block B5
refuses inside both other ceilings, and that vector is in the corpus. So
the retraction this entry asked for must **not** be carried out — the records
it called false were correct as written — and the entry is deleted rather than
marked done, because what it described stopped being true rather than being
fixed.

**Postscript, after the per-block signature ceiling landed.** The clamp is latent again, for a third reason that is
neither of the first two. The per-block signature ceiling `B18` is checked
before any signature is verified and therefore before `B5`, and the gas-densest
Era-0 family spends one signature per 706 sequential gas — so the block that
used to be refused by `B5` is now refused by `B18`, vector 061 records `B18`,
no vector records `B5`, and the necessity sweep never deletes it. **The right
reading is still the one this entry ended on:** "latent, not structural, and
the distinction is corpus-dependent" was accurate, and the clamp stays. What
must NOT be inferred is that `B5` is unreachable — that would need a census of
the shape space, which nobody has taken; see
`core/fold`'s `TestB18BindsBeforeB5OnTheGasDensestFamily` for exactly what is
and is not claimed.

- **`networking.md` §§12.3/12.4 cost arithmetic goes stale when the memoised
  `get-peers` reply and the discovery timer both land.** The per-request figure
  becomes the wrong term and a sentence describing the serving cost as still
  unbounded becomes false. *Deferred:* blocked on the second of the two changes
  landing; the section is not editable from either branch. *Reopens:* whichever of
  the two lands second rewrites §12 with its hardware named.
- **Magnitude figures in comments are transcribed, not derived.** A stale product
  stays a *true* statement while the stronger claim it stands for weakens; eight
  instances of one product, all wrong in the same direction, survived four review
  passes. *Deferred:* touches files other lanes contend, for zero behavioural
  change. *Reopens:* the day the load-bearing products are hoisted into derived
  constants and the comparisons are asserted, so the ninth instance fails a build.

- **`wire.md` §10.2 has no vocabulary for a refusal that also grants.** A
  future-dated announce is `Free` yet refreshes a sync candidacy — an observable
  mutation the four cost classes cannot express. *Deferred:* amending the spec from
  a `node/p2p` PR is the wrong blast radius. *Reopens:* the day §10's owner adds a
  "what it grants" column or an enumerated exception.
- **`wire.md` 10.3's unpoolable-but-valid row names a validity it does not
  establish.** Since the engine stopped running `validity.Check` before `Pool.Add`,
  a certificate refused at a policy gate reaches this row and is not valid; the
  row's reason is also the only `Free` reason not about the sender. *Deferred:*
  spec text only, no implementation change implied. *Reopens:* the day the row is
  relabelled and the epistemic reading is added to §10.5.
- **`sync.md` §4 states the rotation guarantee twice, in non-equivalent forms.**
  The weaker form ("not twice running") sits six lines from the stronger, and the
  cost model leans on the stronger. *Deferred:* docs only; the behaviour was
  re-verified. *Reopens:* the day one form is chosen and stated over the live
  candidate set.
- **Three doc comments cite a wallet test that was renamed and no longer exists.**
  A reader following the sparse-state decision's pointer lands on a test that is
  not there. *Deferred:* the fix is in another package than the unit that found it;
  the class was instead made detectable. *Reopens:* the day the three comments are
  updated to the current name.
- **The `docs/adversarial/` pointer sweep reaches seven of the eleven milestone
  records; `I5.md` and `I7.md` are deliberately unswept.** The convention
  (`CONTRIBUTING.md`, "Node zone") is that a review record is never
  rewritten and owes instead a **link**, from any finding whose fix describes a
  still-live mechanism, to the document that owns that mechanism now. Sixteen
  pointers were located in the tree before they were written — the symbol or test
  named by the finding found in `main`, the owning section read rather than assumed
  — and landed in `I3`, `R1`, `R2`, `I2`, `I1`, `H2-economics` and `I6`; `I4.md`
  was re-read against the same list and found already compliant, an earlier change
  having added the five pointers it was raised for. `make check-links` passes.
  *Deferred:* four residuals, each held back for its own reason. **`I7.md`** is
  under active edit — the ingress-cost units have touched it and `sync.md` with it,
  repeatedly — and the sequencing puts it last, "only when its owner is
  done with it"; nothing establishes that it is. **`I5.md`** is 29 findings across
  73 KB, nearly every one about the sync driver, the peer store or the ingress cost
  contract — the three mechanisms that have moved most since, and whose current
  owners (`sync.md`, `decisions/networking.md` §11, `spec/wire.md` §§9–10) are
  themselves still being edited. Verifying one pointer there is not reading one
  paragraph but establishing which of the many sync-driver, peer-store and
  candidacy changes since the finding's mechanism survived into; done faster it
  produces exactly the wrong pointer the convention first shipped and this entry
  exists to correct, and a wrong
  pointer is worse than the missing one it replaces, so the missing ones are left
  missing and named. **`I6.md`** is swept only across its four numbered findings —
  its `## The pattern`, `## Addendum` and `I6-A1`/`I6-A2` sections were not
  assessed. And **no `LOW / NOTES` bullet and no `## Confidence` list was touched in
  any of the eleven, and no `*Amended.*` block was added anywhere** (the two that
  exist, on I1-L4 and on I2-L6, are unchanged): `I1.md` and
  `I2.md` have never had a `## Confidence` section post-close edited, so the
  forward-list carve-out has no precedent in either file, and the convention names the
  two in-place amendments as "the precedent for the narrow carve-out, not a reason
  to widen it" — pointing those bullets would have widened both carve-outs to
  discharge a convention that asks only for a link on a finding. *Reopens:*
  `I7.md` the day the ingress-cost work closes or the file goes a release without an edit;
  `I5.md` as a unit of its own, sized for 29 findings rather than for a sweep and
  run after `sync.md` §7's open items settle, because a pointer into a section
  about to change is a pointer written twice; and a finding turning out *wrong*
  rather than dated, which is an `*Amended.*` block on that one finding in the form
  `wire.md` §12 uses — a different unit again, deliberately, since the convention's own
  conclusion was that a directory-wide re-sweep is the maintenance burden that
  produced the stale claims in the first place.
- **`wire.go`'s `MaxBlockChunks` comment says 128x where the ratio is 134.2x.** It
  compared 1 GiB against 8 MiB while the capacity is denominated in bytes; it is the
  source two documents copied. *Deferred:* `node/p2p` was not the doc unit's scope.
  *Reopens:* the day the one number is fixed and the two documents' provenance
  sentences are dropped.
- **The `crypto.Sum` preimage-disjointness assumption is in `core/` but not in
  `spec/README.md`.** A reader of `spec/` who adds a protocol word is not told the
  encoded widths are load-bearing. *Deferred:* `spec/` was off-limits during a
  golden-vector regeneration. *Reopens:* the day a paragraph pointing at the
  disjointness test is added to `spec/README.md`.
- **`ARCHITECTURE.md` states chain-id inclusion kills cross-network replay.** True
  only between networks holding *different* ids — silent between a testnet and its
  own respin, which is the case that matters — and only under the allocate-once
  rule the document does not quote. *Deferred:* `docs/` was not the enforcement
  PR's scope and an audit lane was live in the file. *Reopens:* the day the
  allocation clause is quoted beside the claim.
- **`ARCHITECTURE.md` §14 says "SSZ list-roots" and points nowhere.** The reader who
  needs the four fixed values arrives from §14, not from the `spec/README.md`
  section that now defines them. *Deferred:* a 249 KB document with other lanes
  queued against it. *Reopens:* the day §14 (and optionally §5) gains a pointer to
  the normative definition.
- **`BlockByteLimit`'s clamp cannot fire for any set `Validate` accepts, and §15's
  argument names the wrong parameter.** The pairing makes the byte ceiling reach
  capacity exactly at the top of the domain; the parameter that actually enforces
  the transport bound is `SeqGasCapacity`. *Deferred:* no behaviour change; `docs/`
  and `spec/` are other lanes'. *Reopens:* the day §15 draws the redundancy, or the
  day the pairing is relaxed to an inequality and the clamp silently arms.
- **`RELEASE.md` §5's before-tagging block carries a byte-identity check that
  cannot run.** `make build && make build && cmp` gives `cmp` no operands and the
  second build overwrites the first. *Deferred:* left exactly as-is so the
  compressing PR did not assert a command it had not run. *Reopens:* the day it is
  decided whether the line becomes `make repro` or a cheaper local smoke test.
- **`ARCHITECTURE.md` §20 still says the key-epoch budget is per connection.** It is
  per identity now; three statements in the M3/M3.5 bullets are false, and the
  compression deleted two sentences another document quotes verbatim with
  attribution. *Deferred:* changes nothing an implementer would build. *Reopens:*
  the day §20 is corrected — and, optionally, a guard asserting every attributed
  quotation still has a source.
- **The commit sidecar's contract is stated in two non-equivalent sentences.** The
  file comment says "a caller was told"; `Open` restates it as "a clean replay
  accounted for", and they differ on a crash between a commit record's write and
  its barrier returning. *Deferred:* no behaviour is wrong; both are documented at
  their own sites — what is undocumented is that they are two sentences. *Reopens:*
  the day the union is stated as the contract and every reader checked against the
  weaker half.

---

## 5. Deferred code defects

- **Charging a `DROPPED` certificate at `F3`, so a producer pays for what receivers verify** — the
  decision that added `V5`'s upper bound on `Deposit.Amount` and restated
  `docs/ARCHITECTURE.md` §10 two-sidedly explicitly did **not** take this
  option. A `DROPPED` certificate bills nothing, burns nothing and never reaches
  `markSeen`, so a producer can fill its own block to every ceiling with
  certificates that deterministically drop and every receiving node pays the
  bandwidth and one strict Ed25519 verification per declared signature for free.
  Making the failed state check billable would price that — and it moves the
  billing law and the conservation identity, which the pre-launch audit never
  analysed. **What is in place instead:** `B18`, the per-block signature ceiling
  which caps the receiver-side cost at ~6,000 verifications (~4.4
  core-seconds per 30-second interval) regardless of what `V5` declares, checked
  before any signature is verified. `V5`'s bound is **not** what closes this: the
  attack works identically with `Amount = 1` from an unfunded fresh key.
  **Reopens on:** testnet or mainnet measurement showing producers stuffing in
  practice. **Cost of reopening:** a post-launch hard fork — this is inside the
  fold.
- **`B5` has no golden vector again, and the reason changed** — `061` was
  the corpus's `B5` block until the signature ceiling landed. The gas-densest
  Era-0 family spends one signature per 706 sequential gas, so a block dense
  enough to reach `4T` declares more signatures than `B18` admits, and `B18` —
  checked before the loop that verifies a signature — answers first. `061` now
  records `B18`. **What must not be inferred:** that `B5` is unreachable. That
  would need a census of the Era-0 shape space, which nobody has taken and which
  this tree has got wrong four times on the neighbouring question of maximum
  certificate width. `core/fold`'s
  `TestB18BindsBeforeB5OnTheGasDensestFamily` states exactly what is measured —
  `B5` out of reach on the family that used to witness it, and nothing wider.
  `B5` joins `B11` and `B16` as a rule an implementation must enforce with no
  vector to catch it. **Reopens on:** a shape that reaches `4T` inside the
  signature ceiling, at which point the vector comes back.

Real node, storage, or consensus fixes, deferred because the defect is not
remotely reachable or exploitable today, and each ships without a new network.

The free 32-byte runs of `IssueArgs` used to sit here. They are no longer
deferred, and not because they were constrained: the direction was answered the
other way. Field-by-field validation was measured out — three fields, three
different reasons to be unconstrained, one program of four — and the reader is
where the count of carriers stops mattering, which is what shipped. A
format rule over a signer-chosen durable cell would be consensus-affecting and
therefore a genesis-or-era-boundary change, and none is taken. What was left was
an unfixed measurement, and it is fixed in the tree:
`core/validity/free_runs_test.go` holds the three runs free, contiguous and
persisted verbatim twice, and `node/chain/payloadplant_guard_test.go` arms the clause
those runs are load-bearing for.

The missing upper pairing on `cert_list_capacity` also used to sit here,
and it left for the ordinary reason: the fix was always a few lines of node code
with no shipped value behind it, and the condition this file recorded as
reopening it — an era re-pin of `seq_gas_capacity` walking the set into the
region where the count clamp binds inside the domain — is now the exact set
`core/params.Validate` refuses. What the deferral was waiting for could only ever
be observed by the mistake happening, which is the shape of a reopen condition
that should be paid off early rather than watched.

The announce-path non-successor height used to sit here too, and it left by
its own reopening condition rather than by any argument: a header naming this node's
tip as its parent at any height but `tip.Height + 1` describes a block no chain can
contain, and the integer comparison this file was waiting for is now on the
`ParentID == tipID` branch of `OnBlockAnnounceFrom`, ahead of the work check.
`wire.md` §5 step 4 carries the rule and §10.3 the row it needed.

The identity-preserving reset used to sit here, flagged as fitting none of
the five groups because the remedy was a procedure rather than a repository
artifact. It is no longer deferred, and the flag was the thing that was wrong:
the project is published at launch, so an operator procedure that lives only
outside the tree is a procedure nobody finds. The reopen condition this file
recorded — *a reset procedure that isolates the fresh chain without orphaning
peers* — is written down, in `TESTNET.md` §Resets: enumerate every node ever
pointed at the network from the peers files, provisioning records and monitoring;
stop each and wipe or verify-wipe its data directory; start only from empty
directories; record the enumeration in the reset log; and where a known holder
cannot be stopped, mint a new identity instead. The launch transition, which
cannot mint one, carries its own checklist item in `RELEASE.md` §8 and waits
instead. What stays accepted rather than fixed is the unknown holder, and it is
accepted in writing with a watch signal and a response, not by silence — no
checkpoint and no minimum-work constant enters `core/`, because an operator's
decision to abandon a chain is not a fact about the chain.

- **The reassembly byte budget stops describing live memory at the completion
  handoff.** A body in `OnBlock` is held and uncounted; the single-chunk path never
  enters the budget at all. *Deferred:* `[low]` — the peak is transient, not pinned
  by a stalled peer. *Reopens:* the day the `MaxReassemblyBytes` constant is
  re-sized, since the honest figure is larger than the one beside it.
- **The reassembly and withhold budgets are both repaid before the bytes are
  released.** Neither counter is the bound across its own handoff. *Deferred:*
  `[low]`; the cheap fix repairs only the smaller half and the correct one is two
  numbers that must agree. *Reopens:* the day either budget is made to mean its name
  across the handoff.
- **Closing the payload-plant defect needs a record's extent out of band.** A periodic checkpoint index
  bounds the scan's *work*, not the *evidence*; only an fsynced-ahead extent removes
  a damaged record's own payload from the search region. *Deferred:* forces a
  write-ordering constraint, a second commit-path barrier, and a new damage class —
  a durability trade with its own decision record. *Reopens:* the day a store must
  be recoverable after a lost-page fault rather than only refused.
- **An over-budget announcement reaches `recordAnnounce`'s chain lookup without
  paying even a hash.** `recordAnnounce` runs before `work.Check` for a liveness
  reason. *Deferred:* `[low]` — strictly cheaper than the RandomX hash it replaced,
  and candidacy was already obtainable for one hash. *Reopens:* the day a
  per-connection message rate limit is added, which subsumes it.
- **[medium] The node-wide reply ceiling is not sized to the link its operators
  were committed to.** Both directions the owner ratified have landed:
  `Engine.replyByteCeiling` makes the reply total bounded over identities and over
  time by a number the protocol picked rather than by the socket, and
  `MaxConnsPerIdentity` — 4, enforced in `Node.register` against `Conn.PeerKey` —
  collapses the multiplier one keypair could otherwise apply to every per-identity
  budget. What is not closed is the arithmetic the finding opened with: 48 x 266,667
  B/s is about 102 Mbit/s against a design that commits its operators to 2.1
  Mbit/s. *Deferred:* tightening the ceiling to the committed link needs a number
  that is a policy input rather than a derivation, and
  `docs/decisions/capacity-eras.md` §"sustained bandwidth" is waiting on exactly
  that measurement; picking one in the tree would be choosing a protocol constant
  by inference. The cap's own value is *not* deferred — why 4 rather than 2 (2 froze
  sync, because `SyncFrom`'s dedicated leg arrives as a third connection under the
  same identity and `syncOnce` re-routes only on `ErrUndialable`), and why returning
  to 2 would be a protocol change rather than a policy edit, are recorded on the
  constant's own doc comment. *Reopens:* the day the testnet's sustained-bandwidth
  measurement gives the ceiling a link rate to be sized against — at which point the
  per-identity budget becomes the fair share under it and the eclipse-adjacent
  starvation mode gets the liveness test the ratified decision names. Gossip
  forwarding sitting outside both layers is the unmetered-forwarding entry, not this.
- **[low] A spent served-reply budget can be shed through the identity store's
  eviction.** An attacker can re-buy a window by cycling a full store. *Deferred:*
  strictly worse for the attacker than waiting one block interval, at any handshake
  cost above zero. *Reopens:* the day `MaxIdentities` (policy, not protocol) is
  lowered enough to make the eviction path profitable.
- **[low] `get-peers` served is the last `Free` row that must become `Budgeted`.**
  Its interval bounds the frequency, not the bytes. *Deferred:* the interval bounds
  the aggregate three orders of magnitude under the sync budget; the keying
  question (per-connection vs per-identity) needs an argument. *Reopens:* the day
  the reply bytes are charged against the per-identity bucket and `lastGetPeers`'
  keying is decided.
- **A future-dated announcement is exempt from every score the announce path can
  charge.** Dating headers at `now + FTL − 1` buys a permanent amnesty from the work
  check's ban. *Deferred:* a scoring loss, not a resource one — such a message is
  never relayed, requested or pended, and inside the future-time limit every charge
  is live again. *Reopens:* the day a cost class for "refused on this node's clock,
  by a repeat offender" is designed.
- **A `pre-genesis` or `ephemeral` chain id is not held to a genesis at startup.**
  `spec.CheckChainID` closed the main case — the ledger is embedded and a node
  refuses to start on a retired id, or on a live id whose parameters derive a
  genesis other than the pinned one — but ids 1 and 1337 pin nothing, so a
  rewritten mainnet parameter file keeping `chain_id 1` is refused by nothing
  today. *Deferred:* `STATUS_VALUES` says why there is nothing to compare against
  in either case, and for `ephemeral` the absence is the point — a pin there would
  fire on every routine devnet edit. *Reopens:* for `chain_id 1`, the pre-genesis
  freeze, which flips the entry to `live` with the announced genesis id and arms
  the same check that already covers the testnet.
- **`treasury_share_bps = 0` cannot express "no treasury".** The upper end was
  bounded already — `Validate` now refuses 10000, where F11's burst valve would have
  nothing to forfeit — and the accepted range is `[1, 9999]`. Zero stays refused by
  `checkAllPositive`. *Deferred:* the blanket positive rule's value is that it has no
  exceptions, and §14.1 fixes zycord's share at 3% from block 0, so "no treasury" is
  not a configuration this network expresses; a fork wanting none writes 1 bp.
  *Reopens:* the day a network that genuinely pays no treasury has to be expressible.

- **F3 still reserves from any deposit cell.** The third predicate that was offered —
  F3 refusing a non-user deposit address — costs nothing and was not built.
  *Deferred:* dead code in Era 0 (V4/V5 refuse such a certificate statelessly first),
  and it is an F-rule that moves both folds. *Reopens:* the day the fold could reach
  a non-user deposit cell — an Era 1 capability question.
- **The local miner applies its own block without re-deriving the target it
  declared.** Four lines below where it re-checks its own proof of work; the target
  is the one header field given the trust the PoW is not. *Deferred:* contingent on
  a second defect (a miner constructing a wrong target); nothing does today.
  *Reopens:* the day any miner-side bug can mis-scale a target — it would commit a
  fabricated `prev_target` and silently self-fork.
- **A repeat body delivery is deduped before it can refresh its sender's
  candidacy.** The upstream that loses both the announce race and the body race is
  never counted and stays frozen at its Hello height. *Deferred:* moving the refresh
  in front of the dedup gate exposes chain reads on a byte-replayable path.
  *Reopens:* the day a peer's candidacy is judged worth a bounded amount of work on
  the deduped path.
- **Candidacy from delivered bodies moves the candidate set toward the
  connection-set ceiling.** The rotation's one-cycle crossing then binds in more
  meshes, starving a candidate that qualifies only through an unplaceable block.
  *Deferred:* the two effects run in opposite directions and their net is unmeasured;
  a two-node probe is the wrong instrument. *Reopens:* the day a wider-than-two-node
  harness measures `len(candidates)` against the crossing.
- **V2 recomputes the consensus root per certificate, reflectively.** One
  `ConsensusRoot()` is ~28.9 us / 116 allocations on the block-verification path,
  about 2.3% of V2 on a single-signer certificate. *Deferred:* not a regression
  anyone would notice, and a cache needs an invalidation argument it does not have
  (a forgotten memoised field is a silent-fork vector). *Reopens:* the day the ratio
  is pinned by an in-tree benchmark or a memoisation whose invalidation is argued.

- **Undo pruning and reorg admission meet with exactly zero margin.** Off by one, in
  the safe direction, with no test-visible slack — and the documented tip-drop case
  already lands inside the band. *Deferred:* provably tight and therefore correct
  today; adding slack is node-side code. *Reopens:* the day either `undo_depth` or
  the comparison is edited — there is no margin to absorb a mistake, and F10 already
  buys a block of slack for the same class of decision.
- **`LoadKeyFile` passes attacker-supplied Argon2 parameters straight through.**
  `argon2_threads` 0 panics, `InspectKeyFile` accepts it, and `argon2_memory_kib`
  admits 4 TiB, taking the process down with no `recover()`. *Deferred:* availability
  only, no key material exposed, and not reachable by an unprivileged peer.
  *Reopens:* the day a restored/synced key file must be rejected at the moment of
  picking — validate the three KDF parameters in `InspectKeyFile`, not with a
  `recover()`.
- **A drained node-wide key-epoch ceiling shelters the identities the work check
  has already caught.** `own` is false for everyone at once while the ceiling is
  exhausted, so the terminating score is inert for all senders. *Deferred:* a trade
  a fix made, not a defect it uncovered; the refusal stands ahead of `work.Check`,
  so nothing is forwarded, pended or deduped — the loss is score, not resource.
  *Reopens:* the day a non-mutating "is this payer's own budget spent" read is added
  on the ceiling arm.
- **Repairing with a build that predates the commit sidecar leaves a directory the
  newer build refuses permanently.** The old binary shortens the log without
  lowering the sidecar. *Deferred:* needs an operator to run `repair` with a binary
  older than the node's during an incident and take the cut; the outcome is a resync
  of one node, and the safe fixes (bump the format, an operator flag, heal-down) are
  each rejected for a stated reason. *Reopens:* the day mixed-binary repair must be
  made safe rather than documented.

---

## Not classifiable into the five groups

- **[epic] Post-launch hygiene backlog.** This is the tracking epic that the
  `post-launch` findings hang under — a container, not a deferred defect, so it fits
  none of the five classes. Its members are all closed, under the working rule that a
  picked-up item is re-derived from scratch and that anything found
  launch-relevant on re-derivation is promoted. Left here rather than forced into a class.
