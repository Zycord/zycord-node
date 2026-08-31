---
name: Attack finding
about: Something you got the protocol or a node to do that it should not do
title: ""
labels: attack-finding
---

<!--
Read SECURITY.md first if the finding lets somebody take coins, forge a block,
or partition the network. Those go to the address there, not here.

Everything else belongs in the open: a rule that is weaker than it claims, a
griefing vector, a cost the wrong party pays, a node that can be made to spend
without being made to stop.
-->

## What breaks

<!-- One sentence. The defect, not the story. -->

## Which rule

<!--
Name it if you can: the block rules are B0-B18, the fold rules are F1-F13, and
validity is V1-V2. docs/ARCHITECTURE.md is normative and docs/spec/ carries the
wire format. "I do not know which rule" is a fine answer -- say so rather than
guessing, because a wrong pointer costs more than none.
-->

## Reproduction

<!--
Commands, in order, from a clean checkout. State the network (--devnet,
--testnet, or a --params file you attach) and the version: `zcd version`.

A finding nobody can reproduce is a hypothesis. A hypothesis is still welcome
here -- mark it as one.
-->

```
```

## What it costs, and who pays

<!--
Whose money, whose CPU, whose disk, whose liveness. An attack that costs the
attacker more than the victim is a finding about economics rather than
about correctness, and both are wanted -- say which you think it is.
-->

## Severity, as you read it

<!--
Your own reading, not a formality. If you think it is low, say low: a finding
that overstates itself gets read once and discounted afterwards.
-->

- [ ] Consensus: two honest nodes can end on different state
- [ ] Money: coins created, destroyed, or moved without the key
- [ ] Cost: a node can be made to spend unboundedly
- [ ] Liveness: the chain or a node stops making progress
- [ ] Specification: the code and the documents disagree
- [ ] Lower than any of these, or something else
