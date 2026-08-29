# Wallet rules

The adversarial reviews accumulated a behavioural contract for wallets, one finding at a time. This is that contract in one place.

Nothing here is consensus, with one boundary worth naming rather than glossing: rule 1's native half stopped being a way to lose money once the fold began returning what a burn would have stranded instead of leaving it there. The rule survives as hygiene and for the assets the fold cannot reach. Every rule below describes a way to lose money or fees that the protocol permits — deliberately, because the alternative was worse — and that a wallet must therefore prevent. Each rule names the finding that motivates it, so a reader can go and check the argument rather than trust the rule.

**The reference wallet implements these rules. It does not merely document them.** A wallet that only documents them has moved the problem to the user.

**And it implements them once.** `zcd wallet`, `zcd ui` and the desktop application are three interfaces over one `wallet/session`: each builds its certificate there, and `wallet.CheckAll` runs inside that call. A graphical wallet is therefore structurally incapable of being more permissive than the CLI — not because whoever wrote it was careful, but because there is no second code path on which it could be. The irreversible act each rule guards has the same shape in all three: the CLI asks for a typed word, the interfaces ask for a click, and the session refuses outright when neither arrived (`session.SendOptions.Approve` is nil-refuses, so an interface that forgets to ask cannot spend).

---

## 1. Sweep whole cells

*A debit burns a one-shot address. The chain returns what the burn would have stranded — but only in the cells the certificate names, so a balance in an asset it does not mention is still lost forever.*

When spending from a `0x01` address, move the **entire** balance — to the payee and to a change address you control. The certificate carries a `MARK_SPENT` of that address (V6), and after it applies, every read and write under the address fails permanently. There is no second transaction.

**What the chain now does for you, and what it still cannot.** F8b moves whatever a burned address still holds to the certificate's own `RefundTo` cell, at commit, for the address's native balance cell and for every cell the certificate itself names. So under-sweeping no longer destroys drops: it delivers them to your change address instead, on an `APPLIED` certificate, and the outcome reports the amount as `swept`. If that address was burned by some *earlier* certificate the fold delivers nothing and leaves the residual where it was — it never destroys it — and says so in `swept_stranded`, plus `stranded_cells`, a count that reports an *asset* left behind, which no figure in drops can express.

**One new obligation comes with that.** A certificate has one `RefundTo` and may burn one-shot addresses belonging to several signers, so a residual under *your* cell can be delivered to *theirs*: the holder of `RefundTo` gains exactly the understatement, which is precisely what a node lying about your balance produces. So: **never co-sign a certificate that burns a one-shot address of yours and refunds to an address you do not control.** `wallet.CheckBurnedResidualComesHome` enforces it, and it reads no state at all — which is what makes it work against a node that lies about your balance, where `CheckSweepsWholeCell` agrees with the lie by construction. If you genuinely mean to send your change to somebody else, send it with a move, where the amount is in the bytes you sign.

The rule is **membership of your key set**, not equality with one key, and the difference matters for the wallet this protocol is heading towards. Whitepaper §4 generates a one-shot address per payment received and §12's stealth outputs ride the same rail, so a wallet with per-payment keys consolidates several of *its own* one-shot cells in one certificate. A same-key rule would refuse that and force the change into `persistent(K_payment)` — a fresh account per payment, which is exactly the linkage the one-shot rail exists to avoid. `CheckAll` therefore takes the addresses you control, and `session.Owned()` supplies them; a wallet that derives more keys returns more and nothing else changes. What is still out of reach is a balance in an asset the certificate never mentions, so rule 1 stands with its emphasis moved: **name every asset in the certificate that burns the address** — see *What this rule cannot save*, below.

**The deposit is part of that sum, and for some programs it is all of it.** A one-shot address can fund the deposit of any certificate (F-VAL-5), including `ISSUE`, `MINT` and `RETIRE` — which move no value at all. There is no move to sweep with, so the *reservation* is the only thing that empties the cell: reserve the whole balance with `wallet.SweepDeposit` and take the change back through `RefundTo`, which settlement credits in the same fold step. Reserving only the fee ceiling still burns the address, and F8b then delivers the rest to `RefundTo`, so `wallet.SweepDeposit` is the tidier way to write the certificate — it says what it does — rather than the difference between keeping the money and losing it.

The same arithmetic binds a `TRANSFER`: what the moves send plus what the deposit reserves must equal what the cell holds. Sizing a move against the fee ceiling when the deposit reserves more than that asks the cell for more than it has, and the certificate skips against its own guard. `wallet.SweepAmount` computes the number.

> **Motivation:** I1-L4. One-shot semantics are what make a payment unlinkable to the next; the cost is that "spend some of it" is not a thing a one-shot address can do. F-VAL-5 for the deposit half: the moveless programs became able to strand a balance the moment they became able to use a one-shot deposit cell at all.

**`RETIRE` has no sweep of its own.** Its program moves no value by construction (whitepaper §11), and it stays an unconditional pure write: a `RETIRE` of a funded address applies, burns, and F8b returns that address's drops to `RefundTo`. It cannot pay anybody, so the drops go to your own change address and nowhere else. The reference wallet still refuses a `RETIRE` of an address holding a balance, which is now a warning about intent rather than about loss.

**What this rule cannot save.** An `ISSUE` funded from a one-shot address that also holds an asset balance burns that asset balance with it, and Era 0's op set is closed (whitepaper §11). F8b does not reach it and no rule can: the assets under an address are not derivable from a slot, and `core/state` keeps no per-address index, so reaching an unnamed asset would mean scanning the whole cell table in the one stage that does not parallelise. Name the asset — move it in the same `TRANSFER` that burns the address, or move it out first from a different address. If the certificate names the cell, F8b returns whatever the move leaves behind.

**The number "the entire balance" comes from a single, unauthenticated node — state that explicitly.** `zcd wallet sweep` sizes the sweep from `/balance`, and `wallet.CheckSweepsWholeCell` then checks that amount against a `state.State` populated from the *same* RPC answer: the source verifying itself, which always agrees with itself. A node that understates the balance — lying, stale, or simply on a losing fork — makes the CLI sign a certificate that spends less than the real cell holds. **F8b is what makes that cost nothing:** it moves the difference to the `RefundTo` cell, so the certificate still applies, the sweep still completes, and the lie costs not even a skip fee — provided the refund address is one you control, which is the obligation above. `TestUnderstatedBalanceReturnsTheRemainder` (`core/fold`) measures it end to end.

A CLI that talks RPC to a node it does not itself validate has to trust *something* about that node's answers — that is not a bug to fix, it is what a wallet is. Be exact about what the mitigations below are for: not a destroyed balance, but the variants no balance rule reaches — a falsified `spent` flag on the payee or the refund address, and the wrong network entirely.

- `--devnet` / `--params` assert which network the operator means to sign for, the same pair every other `zcd` command already takes. Every node the wallet asks — `--rpc` and `--confirm-rpc` alike — is checked against that assertion and refused on disagreement, instead of network identity being taken from a node alone. This holds for `zcd wallet balance` too, not only for the commands that sign: a balance is the number an operator reads *before* deciding to sweep, so getting it from the wrong network is the same mistake arriving one command earlier.
- `--confirm-rpc NODE` names a second, independent node. If given, every address's balance and spent flag — not just the sweep source's — must be reported identically by both before anything proceeds, which covers the falsified-`spent`-on-the-payee and falsified-`spent`-on-the-refund variants a lying node can produce alongside the sweep-amount case. Those are write-set concerns and this is the only thing here that reaches them. Two things keep it from being independent in name only: a second node whose `chain_id` disagrees is refused (an address is derived from a key, not from a chain, so it exists on every network and reads zero on one that has never seen it — two nodes agreeing about that agree about nothing), and a `--confirm-rpc` naming the endpoint `--rpc` already names is refused outright, because a node cross-checking itself agrees with itself for exactly the reason `CheckSweepsWholeCell` does. The URL comparison is textual: it catches the copy-paste, not two hostnames resolving to one node.
- Before submitting, `zcd wallet sweep` prints the exact numbers and requires the operator to type `sweep` to proceed (`--yes` skips this prompt only, never the checks above it). The irreversible act it stands in front of is the one that *succeeds*: the payee and the refund address, neither of which any node supplies and neither of which any consensus rule can second-guess.

**Where the fix lives.** A certificate's read set is not the wallet's to choose — V3 requires the declared reads to *equal* what `core/validity/derive.go` derives. F8b therefore changes the certificate's **effect**, after the outcome is already decided, rather than its read set: `deriveTransfer` still emits `AccessGuardGE`, nothing a wallet builds changed shape, and a drop of dust racing your sweep costs you nothing — it arrives in your change address with the rest. Why a read-set fix (`AccessGuardEQ`) was rejected — any rule whose **verdict** reads a cell a stranger can credit is a rule a stranger operates, which whitepaper §5's attribution theorem forbids — is argued with its measured cost in [decisions/one-shot-burn-scope.md](decisions/one-shot-burn-scope.md).

> **Motivation:** I1-L4 for the rule; a node that lies about your balance for the trust boundary in how the amount is computed and confirmed, carrying forward the remedy for network identity — the operator asserts the network, rather than taking it from a node.

## 2. `RefundTo` must be an address you can still use

*Settling into a burned cell strands the remainder.*

The deposit's `RefundTo` must name either a **persistent** address you control or a **fresh** one-shot address that this certificate does not burn. V5 rejects *any* `RefundTo` naming an address the certificate's own write set marks spent — not only the deposit cell, which is all it used to check — and V6 rejects the same thing one step earlier for a `DELTA_ADD` credit. What neither can see is an address burned by some *earlier* certificate: the fold burns that remainder rather than writing it into a cell nobody can read, and reports it as `refund_burned` rather than as `refunded`, so a wallet reconciling a balance can tell.

> **Motivation:** R1-C3(i) for the original rule, F-FOLD-1 for its general form, I1-M2 for the case V5 cannot catch.

## 3. One address, one expected payment — and an address once paid is dead for payers too

*A one-shot address that is burned while a payment to it is in flight bills the payer.*

Two obligations, one on each side:

- **Receiving.** Derive a fresh `0x01` address per payment you expect. Never publish one twice. Do not sweep or retire an address you disclosed within the last `TTL_MAX` blocks unless you accept that a payment in flight to it will skip and bill its sender.
- **Sending.** Refuse to pay a one-shot address you can see has already been credited or spent. If a payee hands you an address a second time, treat it as an error, not a convenience.

For anything that will be paid more than once — a merchant, a donation address, a mining payout — use a **persistent (`0x02`) address**. Persistent addresses can never enter the spent registry, so they have *no* burn-grief surface at all. This is the single rule that removes the exposure rather than narrowing it.

> **Motivation:** I1-H3 case 3. It has a malicious variant (a payee burns an address to bill its payers) and a good-faith one (a payee sweeps an address, which marks it spent, racing a second payment). The same rule fixes both. The amplification is `MAX_RETIRE_ADDRS × concurrent payers per address` — the second factor is about 1 under this rule and unbounded without it, which is why it is a rule and not advice.

## 4. Dependent chains: confirm, or accept the risk

*A dependent certificate included without its parent is a legitimate billed skip.*

Increment `Seq` for every certificate that depends on a previous one — receive-then-spend, spend-then-sweep. Within one block the fold commits a signer's certificates in `Seq` order, so a dependent chain in the same block is safe. Across blocks it is not: broadcast `Seq = n+1` only after `Seq = n` has confirmed, or accept that the dependent one may commit alone and skip.

This is not a protocol defect. The signer accepted staleness risk by signing; that is precisely the risk the billing law says is billable.

> **Motivation:** R1-C2, and the residue it leaves.

## 5. Set the maximum generously and the priority honestly

*The maximum is free in fees. It is not free in reserved balance.*

Each market takes two prices. The **maximum** is a solvency bound: once the base fee passes it the certificate is unincludable (B4) and must be re-signed. The **priority** is what a miner is actually paid.

- Raising the maximum costs nothing in fees — the safety buffer is free (R2-H1).
- But the deposit reserves `gas × max`, so the maximum bounds how much balance is locked for one fold step. Size it against the balance actually available, not against a constant.
- A certificate with a long TTL needs more headroom than one with a short TTL, because the base fee has more blocks in which to move.

**The escape hatch for small balances.** A holder who cannot afford a wide maximum must shrink the *window*, not the safety: **sign with a short TTL and re-sign on expiry**, trading lockup for latency. A certificate that only needs to survive five blocks needs a fraction of the headroom of one that must survive two hundred, and a wallet that re-signs on expiry is doing the same job the buffer would have done — just paying for it in round trips instead of in reserved balance.

The wrong response is to keep the long TTL and shrink the maximum, which does not save anything: it makes the certificate strandable exactly when the market moves, which is the case the buffer existed for.

`wallet.BidWithHeadroom` implements the sizing: name the priorities, name a multiple of the current base fees, get a bid. `wallet.CheckHeadroomAffordable` refuses one the balance cannot reserve, and names this rule when it does.

> **Motivation:** R2-H1, including its accepted cost — which was found by the implementer after the reviewer had signed the design off. Neither layer is final.

## 6. Sort moves canonically

*Two orderings of the same moves are two certificate ids with one effect.*

The protocol imposes no order on a `TRANSFER`'s moves: reordering them derives the same reads and writes. That is not a consensus problem — reordering changes the body root and therefore invalidates every signature, so only the signer can produce a variant, and a signer producing one is indistinguishable from a signer authorising a second payment, each with its own deposit and its own bill.

It is a wallet problem. Without a canonical order, a retry of the same logical payment produces a different id, and the wallet cannot tell "already sent" from "sent twice". `wallet.Transfer` sorts by asset, source, destination, then amount, so a retry reproduces the id.

Sorting the moves is the whole of what a retry has to get right *about the program*; the rest of the body — `Seq`, `TTL`, `Deposit`, `FeeBid` — has to be reproduced too, because all of it is in the id. What a retry does **not** have to reproduce is the signature: the id's preimage excludes the signature list, so a retry re-signed at a fresh Ed25519 nonce is the same id and the network refuses it as the duplicate it is. Idempotency is a property the protocol provides, for every wallet rather than for the careful ones.

> **Motivation:** R2-M2.

## 7. Never hand out a seed

The seed is the key. Anyone who reads it owns everything both of its addresses hold — the one-shot and the persistent, which are unrelated on chain but derived from the same key.

Key files are always encrypted — Argon2id over the passphrase, AES-256-GCM over the seed, both with their parameters stored in the file so that a user locked out of this binary can recover with any language's standard library. There is no flag to write one unencrypted.

Writing holds two properties at once, and both are about the same sentence: losing one is losing money.

- **Never silently overwrite.** A key file already at the destination is left untouched and the write fails.
- **Never leave a torn one.** The seed goes to a temporary file in the same directory, is fsynced there, and only then is published under its final name in a single filesystem operation — so a crash mid-write leaves the destination absent, never a truncated file. That matters because a truncated key file reports itself as a *wrong passphrase*, and the write that would recover it is exactly the write the no-clobber rule refuses.

Both hold on every filesystem the CLI was measured against, **FAT32 and exFAT included** — the formats a cold-storage USB backup is most likely to use.

Publishing the fsynced temp file under its final name is done with an *exclusive rename* — `renameat2(RENAME_NOREPLACE)` on Linux, `renamex_np(RENAME_EXCL)` on macOS, `MoveFileEx` without `MOVEFILE_REPLACE_EXISTING` on Windows — which publishes and refuses an existing destination in the same call, so neither guarantee rests on a check. Measured working on real volumes: Linux vfat and exfat (kernel 6.12), macOS FAT32, APFS, ext4/overlayfs, Windows NTFS and exFAT. Where a platform has no exclusive rename of its own, publishing falls back to a hard link, which also refuses atomically; and where a filesystem has neither, to a plain rename guarded by a check made immediately before it. That last tier keeps crash-safety in full but its refusal is *not* atomic — two copies of this CLI writing one path at the same instant could both pass the check. No measured filesystem reaches that tier; it exists so an unmeasured one degrades in a defined order rather than failing outright.

**Every platform needs its own tier 1; the hard-link tier is not a substitute for it.** The per-platform table, and the measurement that shows why (`os.Link` fails on exFAT with `ERROR_INVALID_FUNCTION`, which is not "the destination exists" and so does not stop the fall-through), are in the header comment of `wallet/atomicfile.go`. `wallet/atomicfile_exclusive_test.go` fails if a platform drops FAT32 or exFAT to the racy tier.

Three limits worth stating rather than glossing. The first is about that last tier; the other two are properties of the FAT formats rather than of this code, unchanged by anything this code does, and no write to FAT32 can do better:

- On the check-then-rename tier only, the no-clobber refusal is racy as described above. It is an accident hazard, not a security boundary: reaching it at all requires a filesystem with neither an exclusive rename nor hard links.
- FAT32 and exFAT have no journal, so "in the same syscall" there is as atomic as the format makes it. If a publish is interrupted on FAT and reports failure, check the destination before rerunning. It is still categorically better than writing the seed straight to its final name.
- FAT32 and exFAT have no Unix permission bits, so the `0600` a key file is created with does not survive on them — the mount options decide. On Linux the default `fmask` typically leaves it world-readable; macOS mounts such volumes `noowners`, which reports `0700` but enforces nothing. Either way: **an encrypted key file on a FAT-formatted stick is protected by its passphrase and by nothing else.** Choose the passphrase accordingly.

Passphrases are read from the terminal without echo, never from a flag. A passphrase on a command line is in the shell history and in the process table.

## 8. Refuse what the network will refuse, before you say `submitted`

*A wallet that reports success for something the network can only discard has moved the failure somewhere the user will never look.*

Two shapes of this, both found in the field.

- **Bytes no peer can decode.** The codec is an authority in its own right, with rules `validity.Check` does not restate. A fee bid whose priority exceeds its own maximum passed the builder and the validator and was refused by `UnmarshalCertificate` — on every ingress path there is, so the certificate could never reach a peer, never be included, and never be explained. `validity.CheckCanonical` now repeats the decoder's canonical-form rule for both markets, and `wallet.Builder.Build` asserts the property directly: whatever it emits, `types.UnmarshalCertificate` accepts. Asserting the property rather than enumerating the rules is deliberate — a rule the codec gains later is covered the day it is added.
- **A transfer the fold can only skip.** A transfer above the source's balance breaks no rule. Every node admits it and no producer gains by including it, so it is normally evicted at TTL having told the signer nothing. Normally, not always, and the difference is why this is a refusal rather than a warning: nothing *refuses* a producer that includes it anyway, and the fold then settles it at `skip_fee` — burned out of the deposit and paid to nobody (whitepaper §5). The bad case is not "no effect", it is "the fee was burned and the value never moved". The balance is already fetched for rule 5's reserve check; `wallet.CheckMovesAreCovered` compares it against what the certificate actually takes out of each cell — the moves plus the deposit reservation, since a source that is also the deposit cell gives up both.

**The escape hatch, and its exact limit.** `zcd wallet send --force` (`session.SendOptions.Force`) submits despite the balance comparison, because a deposit expected to land inside the TTL window makes the same certificate apply and the wallet cannot see the future. It bypasses that one refusal and nothing else: the V-rules, the codec round-trip, the network-identity assertion, rule 5's reserve refusal and the one-shot drain approval all still hold, and the preview a front end renders carries the refusal that was overridden. `--force` cannot make an invalid certificate valid; it can only submit a valid one that may skip — and a skip is not free. If the expected deposit does not arrive and a producer includes the certificate regardless, the fold settles it at `skip_fee`, burned out of the deposit. That is the one concrete cost the override buys, it is charged to the person who typed the flag, and the flag's own help text says so.

> **Motivation:** the two refusals this section names — bytes no peer can decode, and a transfer the fold can only skip.

---

## Checklist for a wallet implementation

- [ ] Spending from `0x01` moves the whole balance, counting the deposit reservation as part of it — including on programs with no moves at all (rule 1).
- [ ] `RETIRE` refuses a target that still holds a balance (rule 1).
- [ ] The wallet does not treat the node's report of that balance as beyond question: network identity is asserted by the operator and checked against every node asked, a second independent source can be cross-checked, and the exact numbers are confirmed before an irreversible sweep submits (rule 1).
- [ ] `RefundTo` is validated as persistent-or-fresh before signing (rule 2).
- [ ] Receiving derives a fresh address per expected payment (rule 3).
- [ ] Sending refuses a one-shot address that is already credited or spent (rule 3).
- [ ] Merchant and payout addresses default to `0x02` (rule 3). A mining payout is not a default but a requirement: `zycordd --payout` refuses a `0x01` address outright, because a payout is credited every block that node produces, and the shared maturity ring still holds that miner's share of the last `COINBASE_MATURITY` blocks — all of which the fold burns from the moment the address is spent once.
- [ ] `Seq` increments per dependent certificate, and the wallet waits for confirmation before broadcasting the next — or says out loud that it is not (rule 4).
- [ ] Fee maxima are sized from available balance and TTL, not hardcoded; a balance too small for the headroom shortens the TTL rather than the safety (rule 5).
- [ ] Moves are sorted canonically, so a retry reproduces the certificate id (rule 6).
- [ ] Key files are encrypted, written durably with no silent overwrite, and passphrases never reach a flag (rule 7).
- [ ] Nothing is signed that its own encoding cannot be decoded back from, and nothing is submitted that the source balance cannot cover — with any override named, narrow, and reported in the preview (rule 8).

## What enforces each rule

| Rule | Enforced by |
|---|---|
| 1 — sweep whole cells | `wallet.CheckSweepsWholeCell` (moves *and* the deposit reservation, every program kind); `wallet.SweepDeposit` for a moveless program; `zcd wallet sweep` computes the amount, asserts network identity via `--devnet`/`--params`, optionally cross-checks balances and spent flags via `--confirm-rpc`, and requires a typed confirmation of the exact numbers before submitting |
| 2 — usable `RefundTo` | V5 and V6 for everything the certificate burns itself, `wallet.CheckRefundDestination` for an address burned earlier |
| 3 — one address, one payment | `wallet.CheckPayeeIsFresh`; `zcd wallet new` recommends `0x02`; `zycordd --payout` refuses anything but `0x02` |
| 4 — dependent chains | wallet discipline; the CLI sends one certificate at a time |
| 5 — fee sizing | `wallet.BidWithHeadroom`, `wallet.CheckHeadroomAffordable` |
| 6 — canonical moves | `wallet.Transfer` |
| 7 — key handling | `wallet.SaveKeyFile` / `LoadKeyFile`; no unencrypted path exists; writes are durable and never clobber (`writeFileNoClobber`) |
| 8 — refuse what the network refuses | `validity.CheckCanonical` (V1, priority ≤ maximum in each market); `wallet.Builder.Build`'s `UnmarshalCertificate(MarshalSSZ())` round-trip; `wallet.CheckMovesAreCovered`, run last in `wallet.CheckAll` so `--force` cannot hide the other rules behind it |
