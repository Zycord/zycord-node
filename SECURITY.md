# Security

## Status

**Pre-genesis.** There is no live network, no coin, and nothing at stake yet. That makes this the only period in the project's life when a critical finding costs nothing to fix — which is exactly why we want them now.

## Reporting

Use GitHub's **private vulnerability reporting** on this repository (Security → Report a vulnerability). It is the only channel that is both private and does not require you to identify yourself to anyone.

Please do not open a public issue for anything in the "critical" list below.

Include, as far as you can:

- which rule is broken, by number if possible (`V4`, `B3`, `F7`, …);
- the attack: who does what, in what order, and what they gain;
- a reproduction — a test in `core/fold` or a scenario in `sim/` is ideal, and a paragraph is fine.

You will get an acknowledgement. You will not be asked who you are.

## What counts as critical

These are the findings we most want before genesis, in rough order of how badly they would hurt:

1. **A way to make one signature pay twice.** Any path — proposer, reorg, encoding, replay — by which a certificate id is billed more than once on a canonical chain. This is the billing law, and the whole economic model rests on it.
2. **A way to bill a third party.** Any way to make somebody else's certificate skip. The Era-0 op set is claimed to be poisoning-immune with one stated exception ([I1-H3](docs/adversarial/I1.md)); a second exception is a critical finding.
3. **A way to create value.** Any path by which the native supply grows other than by `emission(height)`, or by which a capped asset exceeds its cap. The subsidy is split 97/3 between the block's producer and the treasury cell, so this covers both halves: a split that does not sum to the subsidy creates or destroys drops, and any write to the treasury cell other than F11's credit is value from nowhere.
4. **A consensus split.** Any input on which two correct-looking implementations, or two nodes with different pruning or timing histories, disagree about validity or about the state root.
5. **A way to make a valid block unprovable or an invalid block acceptable.** Encoding ambiguity, non-canonical bytes that decode, offset arithmetic, or a hash that is not domain separated.
6. **Anything that makes the fold non-deterministic.** Map iteration, timing, platform-dependent arithmetic, unbounded work.

Findings in `node/`, `wallet/` and `sim/` matter too — they are simply not existential in the same way, because they are replaceable plumbing.

## Scope

In scope: everything in this repository, and the parameter sets in `spec/`.

Out of scope: third-party services, anything about the website or social accounts (there are none that this repository vouches for), and denial-of-service against a machine you own.

## Disclosure

Before genesis: we will fix, publish the fix, and credit the reporter under whatever name they choose — including none.

After genesis: coordinated disclosure with an embargo long enough for node operators to upgrade, because there is no admin key, no pause button, and no way to protect users except by getting patched binaries into their hands first.

## Bounties

There is no bounty pool today, and no way to fund one from the protocol. There is no premine and no foundation; the treasury cell of [whitepaper §14.1](docs/whitepaper.md) does not exist in the code yet, accrues nothing until genesis, and cannot be spent from before Era 2 — genesis contains no key for it. A community-funded pool is planned for the public attack-net at M4 and will be announced in this repository. Anyone who tells you otherwise is not us.

## What we cannot promise

We are not a company. There is no on-call rotation and no SLA. What there is: a small, auditable consensus surface, public vectors, reproducible builds, and a strong preference for being told we are wrong before a million people are relying on us being right.
