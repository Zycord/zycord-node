---
name: Benchmark result
about: Numbers from your machine, so the whitepaper's figures stop being one desktop's
title: ""
labels: benchmark
---

<!--
The whitepaper's section 15 asks people to post their figures. This is where.

The figures there were measured on one machine, and one machine is not a
distribution: what a reader needs is the spread, and the spread only exists if
other people run it.
-->

## Machine

<!--
Only as far as the measurement requires -- the same rule the project holds
itself to. Core and thread count, whether it was otherwise idle, and the
operating system. A CPU model is welcome and is yours to disclose; it is not
required, and nothing here asks for a serial number or a hostname.
-->

- Cores / threads:
- Otherwise idle:
- Operating system:
- CPU (optional):

## Version

<!-- `zcd version`, verbatim, including the engine line. -->

```
```

## Output

<!--
`make bench`, verbatim and unedited. Do not trim it to the lines that look
relevant: the ones that look irrelevant are how somebody else notices that
your run and theirs measured different things.

Read the note in docs/RELEASE.md first if you are publishing a figure rather
than reporting one -- benchmarks in a single process interfere with each other,
and a transcript read top to bottom reports the later ones slower than they
are.
-->

```
```

## Anything surprising

<!--
A number far from the published one is the most useful thing you can post,
whichever direction it is in.
-->
