# Zycord — A sparse reader guards itself; `state.State` keeps one answer for an absent cell

**Scope:** what `core/state.State` should do about the fact that it cannot tell an **absent** cell from a **zero** one, on either of its two axes, given that the absent answer is the benign one and three of the four defects found so far therefore failed *open*. Raised as the one cost that survived the `session.View` fix, and stated in code as an accepted one.

**Verdict: nothing at the type, deliberately.** A holder of a sparse `State` records what it fetched and refuses what it cannot answer, beside its own fetch. `wallet/session.View` is the reference implementation. `state.State` keeps exactly one answer for an absent cell, because zero-is-absence is a consensus requirement rather than an implementation convenience (whitepaper §4, §5/R2-M2) — and, less obviously, because the alternative puts a *third answer* into the one package whose whole job is that there is no third answer.

The argument is not that the conflation is harmless — it has fixed open four times. It is that the population which can observe it is **one call site**, so the reuse a shared type would buy is currently zero; and that `core/state` is the wrong home for such a type even once it is worth building, because sparseness is the one thing that package's invariant says is not representable. Population, then placement.

What this argument is **not**, since two earlier drafts of this paragraph claimed it: it is *not* that the guard at that site is derived from source rather than hand-written, and it is *not* that the type-level shapes would make it weaker. §4 withdraws both. The guard is six hand-written lookups, and on detection the rejected shape is conceded **better**. The defeat is placement alone.

Because "the population is one" is a measurement and not a property, it is pinned: `core/state/sparse_population_test.go` classifies every construction of a `state.State` outside the package and fails on an unregistered one. Without that pin this document is a comment, and a comment is what this issue is about.

---

## 1. The mechanism, on both axes

Both axes are one design decision seen from two sides, and both are in `core/state/state.go` at this head.

**Balances.** `Set` (`core/state/state.go:190`) deletes the entry when the value is zero, and `Get` (`core/state/state.go:185`) is a bare map read, so an absent key yields `u256`'s zero value:

- a cell drained to zero, and
- a cell that was never written,

are the same cell, and both read `0`. There is no third result.

**Spent flags.** `MarkSpent` (`core/state/state.go:224`) is only ever called for an address a caller actually learned was spent, and `IsSpent` (`core/state/state.go:215`) is a bare set-membership test, so:

- an address that is live, and
- an address nobody has heard of,

both read `IsSpent == false`.

**The direction is what makes this a defect rather than a fact.** In every instance found, the absent value is the *benign* one: an empty source, a fresh payee, a live refund destination. A reader that has not fetched a cell does not get an error. It gets a pass.

**A third construction route, which the two above hide.** `State`'s fields are all unexported, so `state.State{}` sets none of them — but the literal is still legal Go from any package, as are `var s state.State`, `new(state.State)`, a struct field of type `state.State`, and equally `make([]state.State, n)`, `map[K]state.State`, an array of them, or a named type declared over it. That list is why the test matches the value *type name* rather than the syntactic forms: written as a list of forms it was measured incomplete in four ways. Every one of them yields a `State` whose maps are nil, and a nil map *reads*: `Get` returns zero for every slot, `IsSpent` returns false for every address, `Seen` returns false for every id. **The zero value of the exported type is a fully readable state that answers every question with the benign answer and never errors** — this defect in its purest form, reachable without calling anything. No non-test file outside the package takes that route today; `TestNoPackageOutsideStateBuildsAStateByItsZeroValue` is what says so on the day one does.

## 2. What is ruled out, and stays ruled out

**Making `Set` keep zeros.** Whitepaper §4 (line 122 at this head) states it as a consensus requirement, load-bearing twice over: it lets a guard or an exact read name `0` without asking whether the slot exists, and it keeps the state root a function of the *state* rather than of the history that produced it. An explicitly stored zero is a second encoding of one state — §5/R2-M2, one state transition has one encoding — and two nodes reaching identical balances by different routes would commit to different roots. That is a chain split arriving by bookkeeping.

**A second reason, not in the issue and worth recording.** The semantics are implemented **twice**. `sim/refold` is the deliberately naive re-derivation the differential runner checks `core/fold` against, and its `Set` (`sim/refold/refold.go:180`) deletes on zero identically, over sorted slices rather than a map. Any change to the *meaning* of absence would have to be mirrored there, and `sim/refold`'s entire value is that it is an independent re-derivation — teaching it about fetched-ness would make the two folds agree by construction about the very thing the runner exists to check independently. This is the `core/`-scoped-sweep trap of the contributor rules in its natural habitat: the second copy is outside `core/`.

## 3. The population is one, which is half the argument

The issue's framing is "four site-local fixes for one type-level property", which reads as four *sites*. Re-derived at this head, it is not. All four instances are **rules in one package reached through one call site**:

| instance | what it does | direction | where the rule lives |
|---|---|---|---|
| asset source | a view cannot represent a non-native asset cell; source reads zero, move refused as `ErrMoveExceedsBalance` | refuses wrongly | `wallet/policy.go` |
| RETIRE target | unfetched RETIRE target reads zero, zero reads as "already empty", `CheckSweepsWholeCell` accepts, balance burned with the address | **accepts wrongly** | `wallet/policy.go` |
| payee | unfetched one-shot payee reads not-spent and empty, which is exactly "fresh" | **accepts wrongly** | `wallet/policy.go` |
| refund destination | unfetched refund destination reads live, remainder delivered into an address that burned its authority (I1-M2) | **accepts wrongly** | `wallet/policy.go` |

Four *rules*, one *reader*. And the guard that closed them did not add a fifth rule-local fix: it added one guard at the one site, whose required set is **derived from `package wallet`'s source** by `wallet.TestEveryStateReadInPackageWalletIsPinnedToACoverageAxis`, so a newly added rule cannot be added quietly.

The measurement, at this head. `state.New()` has **five** non-test call sites in the tree, and outside package `state` there is no other way to obtain one — every field is unexported, and `Clone` propagates its receiver's sparseness rather than originating it:

| site | classification | why |
|---|---|---|
| `core/genesis/genesis.go::Build` | dense | the pre-genesis state, empty in fact rather than unfetched |
| `node/chain/store.go::OpenWith` | dense | the chain's own state, filled by folding every block |
| `spec/gen/main.go::genesisVectors` | dense | a golden vector's pre-state; a vector declares the whole state it folds against |
| `spec/vector.go::BuildState` | dense | the same, read back from `PreState` |
| `wallet/session/session.go::FetchState` | **sparse** | the few cells one node was asked about |

Every other reader in the tree — `core/fold`, `sim/refold`, `node/chain`, `node/mempool`, `node/miner`, `node/rpc`, `sim/harness`, `spec` — reads the chain's own state or a vector's declared pre-state, both dense by construction. For them, an absent cell *is* an empty one and there is nothing to disambiguate.

And `wallet.CheckAll`, the entry point through which all four defects were reached, has exactly **one** non-test call site: `wallet/session/send.go:323`, immediately preceded by `view.CoversCertificate(cert)` at `wallet/session/send.go:319`.

## 4. Rejected alternatives

### A `SparseView` in `core/state`, with `Get`/`IsSpent` returning `(value, known bool)`

The proposal's own claim is reusability: `session.View` is this type hand-rolled, so lift it. That claim is **correct**, and the defeat is therefore not about what the shape can detect — it can detect everything the guard that was built detects. It is about where the type would live. A concession first, then two defeats, on the proposal's own terms.

**It would have caught all four, and that is not what defeats it.** Stated first because an earlier draft of this document claimed the opposite — that "the rule never asked" — and that claim is false at this head. Every one of the four instances is an explicit read inside a rule, and a `(value, known bool)` return at that read would have separated every one of them:

| instance | the read, at this head | what `known == false` would have done |
|---|---|---|
| asset source | `CheckMovesAreCovered`, `wallet/policy.go:395` | refused as unfetched instead of as `ErrMoveExceedsBalance` |
| RETIRE target | `CheckSweepsWholeCell`, `wallet/policy.go:89` | refused instead of reading the unfetched cell as already-empty |
| payee | `CheckPayeeIsFresh`, `wallet/policy.go:228` and `:231` | refused instead of reading unfetched as fresh |
| refund destination | `CheckRefundDestination`, `wallet/policy.go:183` | refused instead of reading unfetched as live |

**And on one axis it is better than what was built, which this document concedes rather than argues away.** A second draft claimed the guard actually built works by "one decision derived from source" against shape 1's six. That was false and is withdrawn. `CoversCertificate` is three functions containing **exactly six** hand-written fetched-set lookups — the deposit cell, each TRANSFER move source, each RETIRE target, `fetchedSpent[m.Dst]`, `fetched[BalanceSlot(m.Dst, m.Asset)]`, and `fetchedSpent[RefundTo.Addr]`. Six against six. Each of those six *mirrors*, in a different file from the rule, which cells that rule will read; `wallet/session/session.go:336` says so outright — "The one-shot test mirrors `CheckPayeeIsFresh`'s own exactly." The source-derived term, `wallet.TestEveryStateReadInPackageWalletIsPinnedToACoverageAxis`, is a **test over `package wallet`'s source**, not a part of the guard, and it applies to shape 1 unchanged. Cancel it from both sides and the comparison inverts: six mirrors in another file, versus six `known`s at the read. **A mirror can drift from what it mirrors; a `known` at the read cannot, because it *is* the read** — and §3's table records that two of the four instances (the RETIRE-target mirror scoped to debited cells only, and both the payee and the refund axes missing outright) are failures of the mirror, not of the type. That drift risk is a real cost of this verdict and is carried in §5.

They are also **not mutually exclusive**, which is what finally disposes of the comparison. Shape 1 asks whether the wrapper "should be a reusable type in `core/state`"; nothing in it asks that `CheckAll` consume `known`. `CoversCertificate` survives verbatim on top of a `SparseView`. So the two are not rival mechanisms, and the only question shape 1 actually poses is **placement** — which the two defeats below answer.

**It puts a third answer inside the package whose job is that there is no third answer.** Whitepaper §4: zero-is-absence "is what lets a guard or an exact read name `0` without asking whether the slot exists — *there is no third answer to disambiguate*." A `SparseView` in `core/state` returning `(value, known bool)` is a third answer, in that namespace, importable by `core/fold`. Even granting that consensus paths never construct one, the next fold author has an API in scope saying absence is representable. Sparseness is not a property `core/state` should be able to express, because a fold state is never sparse — this is *make the wrong state unrepresentable* pointed the other way, and it is the same axis as the issue itself.

**It inverts the dependency.** `core/` imports nothing but the standard library, and `core/state`'s own package comment records that it is the only place in `core/` holding a map at all, under a discipline (never iterated in consensus order). This shape adds two more maps to the consensus kernel whose only consumer is a wallet.

### A debug/test-only strict mode that panics on a read of an unfetched cell

**It is an unobservable defence, and the standing preference is to delete one rather than document it.** The issue concedes it "proves nothing about production paths". The one production path is already guarded, so the mode would run only where the guard already holds.

**It is not independent of the first alternative — it *is* the first alternative, plus a panic.** To know a cell is unfetched, a strict `State` must carry the fetched set. That is `SparseView` with a worse failure mode: a panic raised from a `core/` package on a consensus type.

**It requires either a process-global mode switch on a consensus type or a build tag.** The first is exactly the ambient, order-dependent state `core/`'s constraints exist to keep out. The second means the tested binary is not the shipped binary, which is the standing objection to any debug-only consensus behaviour.

## 5. What this costs, stated as costs

- **The next sparse holder still starts from the fail-open default.** Nothing about `state.State` changed, so an author who adds one and does not read this document gets a type that answers every unasked question benignly. What is different is that they cannot do it *silently*: the classification pin fails on the unregistered construction, and its failure message names the choice. That is a strictly weaker guarantee than a type that cannot be misused, and it is accepted, not argued away.
- **The pin is a whole-tree source scan, so it fails on changes made elsewhere.** A contributor adding a `state.New()` in an unrelated package gets a failing test in `core/state`. That is the intended coupling — the population count is the claim — but it is a real cost to an unrelated change, paid in one registry line.
- **The zero-value route is counted, not closed — declined on cost, not on impossibility.** An earlier draft said "Go cannot forbid a composite literal of an exported type". That is true and answers the wrong question: the literal cannot be forbidden, but the resulting *value* can be made unreadable. `type State struct{ *impl }` turns every zero-value route — literal, `var`, `new`, slice, map, array, named type, and the dot-imported one — into an immediate nil-pointer panic on the first read, with no branch in `Get` and no consensus value moved. It is declined because it costs a pointer indirection on the fold's hottest read and a `core/` change to close a route with no caller, **not** because it is impossible. On an issue whose own axis is *make the wrong state structurally unrepresentable*, that distinction is the whole difference between a trade and an excuse, and a future reader weighing the indirection differently should take the structural fix.
- **The pin's guarantee, at its true size.** *Every construction that mentions `state.New` or `state.State` directly, in a file that imports the package non-dot, and whose enclosing key is unique to it.* Each qualifier is a measured escape rather than a hedge. **Recognition is complete and can say why**: `go doc -all ./core/state` shows exactly one exported function returning a `*State` without already holding one — `New` — while `Clone` is a method and therefore propagates rather than originates, and there is no `Decode`, `Parse`, `From*`, `Load` or `Unmarshal`. So every construction, in any form anyone invents, must name one of **two identifiers**, and the scan keys on the identifier rather than the form. What is *not* complete sits one step past recognition, in **selection and attribution**: two constructions under one enclosing key would have let the second inherit the first's classification and named guard (now checked at the map write, after a second `state.New()` inside the registered `(*Session).FetchState` and a closure inside the registered dense `genesis.Build` were both measured passing every pin); and a mention of the type *under a pointer* is skipped by design, which the `reflect` type-witness idiom `(*state.State)(nil)` exploits. That last one is **alarmed rather than closed**: a file importing the state package together with `reflect` or `unsafe` is reported, including through a dot import, because the escape is a capability rather than a form — but the check watches *imports*, not *uses*, so it cannot tell a fabrication from a legitimate `reflect` call, and it is blind to one routed through a helper package that imports `reflect` without importing state. That last route is a **propagation** (the helper constructs, the caller receives), so it belongs to the propagation gap named at the end of this bullet rather than to the construction scan. **Propagation remains outside all of it** — a sparse `*state.State` assigned to a field, passed across a package boundary or returned from an accessor is not a creation and is not seen. `Clone` likewise propagates its receiver's sparseness rather than originating it, and at this head all seven non-test `.Clone()` calls have dense receivers, with none anywhere in `wallet/`, so the sparse view is never cloned. That gap is carried deliberately rather than closed. Its one measured holder — `cmd/zcd`'s `nodeState`, a `*state.State` copied out of a `session.View` with the coverage sets left behind, written once and read nowhere — was **deleted** rather than documented, which removed `cmd/zcd`'s only import of the package; `TestPackageMainDoesNotImportCoreState` is what says so if it comes back. No holder of a propagated sparse state remains at this head, so the limitation is now stated on the registry's own doc comment rather than inferred from an instance, and the two routes it cannot see — a copy across a package boundary, and a fabrication split so that neither file holds both `reflect` and this package — are named there.
- **The guard this verdict keeps is a mirror, and a mirror can drift.** `CoversCertificate` re-derives, in `wallet/session/session.go`, which cells each rule in `wallet/policy.go` will read — six lookups mirroring six reads, in a different file from the reads, with `session.go:336` stating the mirroring outright ("The one-shot test mirrors `CheckPayeeIsFresh`'s own exactly"). A `known` returned at the read cannot drift from the read because it *is* the read; this can, and §3's table records the two measured instances of it doing so: the RETIRE-target mirror covered debited cells only, and the mirror missed the payee and the refund destination outright. `wallet.TestEveryStateReadInPackageWalletIsPinnedToACoverageAxis` is what makes the drift loud rather than silent, but it is a test over source and not a property of the guard, so this cost is carried, not closed. It is the price of choosing placement over shape, and a third mirror failure is grounds to revisit §4 rather than to add a seventh lookup.
- **`session.View`'s guard remains scoped to one certificate and one wallet.** The guard's own claim holds unchanged: what is pinned is that every read this wallet's rules perform has an answer, not that a read elsewhere cannot be conflated.

## 6. What is pinned by tests

| Test | Property |
|---|---|
| `state.TestEveryStateConstructionOutsideThePackageIsClassified` | every construction of a `state.State` outside the package, in non-test source, is registered with a dense/sparse classification; **no two constructions share one registry key**, so a second one cannot inherit the first's classification and guard; and no file reaching the package also imports `reflect` or `unsafe`, which could build one without naming it in a readable form |
| `state.TestTheClassificationRegistryHasNoStaleEntries` | the registry names no site that no longer exists, so the count stays a count |
| `state.TestEveryClassificationCarriesItsReasonAndAGuardIffItIsSparse` | a classification carries its reason; sparse implies a named guard, and dense implies none |
| `state.TestNoPackageOutsideStateBuildsAStateByItsZeroValue` | the zero-value construction route — which the `state.New()` scan structurally cannot see — is unused outside the package |
| `state.TestTheScanRefusesToPassByMeasuringNothing` | the scan parsed every non-test `.go` file the tree holds, found the sparse site this document names, and refuses to descend only into directories that hold no Go source — the file set compared in both directions against a walk that shares nothing with the scan but the module root, and the skip list checked against an independent one |
| `wallet.TestEveryStateReadInPackageWalletIsPinnedToACoverageAxis` | every state read `wallet.CheckAll` performs has a covering axis in `session.View` |
| `state.TestEveryIdentifierThisFileCitesInACommentExists` | every camel-cased identifier this instrument cites in a comment — exported and unexported alike — resolves somewhere in the tree, so a citation in it cannot rot the way three earlier citations in it did |
| `state.TestEveryEntryInTheCitationAllowlistIsUsedAndExplained` | the three tokens exempted from that check each carry a reason and are each still cited, so the exemption list cannot become the drain the check exists to plug |
| `state.TestEveryNamedGuardTestExists` | the test a `sparseGuarded` entry names as pinning its guard is actually declared in the tree, so the citation cannot rot |
| `session.TestEachCoverageAxisRefusesOnItsOwnSeparatingInput` | each coverage axis refuses on its own separating input |
| `main.TestPackageMainDoesNotImportCoreState` | `cmd/zcd` reaches `core/state` from no non-test file, so the CLI cannot hold a sparse state without the `session.View` that answers for it — an import tripwire scoped to that one package, making no claim about any other |

## 7. When to reopen this

The verdict is a function of the population, and the population is measured rather than assumed. Reopen if any of these becomes true:

- **A second sparse holder appears** that cannot reuse `session.View` — for instance a light client, or a node serving reads from a partial state. Two sparse holders with two hand-rolled guards is the point at which a shared type earns its keep, and the pin is what will surface it. **When that happens, the shared type belongs in `wallet/` or in a package of its own outside `core/` — not in `core/state`.** The two defeats in §4 are about placement, not about the shape: lifting `session.View` into a reusable type is reasonable and may become necessary, but putting it under `core/` reintroduces both the third answer in the package whose invariant is that there is none, and the consensus kernel carrying a type no consensus path uses. A reopen that forgets this re-proposes exactly what was rejected here.
- **A rule needs to distinguish absent from zero to reach a *verdict***, rather than to decide whether it may run. Everything here assumes the distinction is a pre-flight question. A rule whose answer genuinely depends on it is a different problem.
- **The zero-value route acquires a user.** The registry would then be classifying a construction that never called `New`, and closing the route becomes cheaper than counting it.
