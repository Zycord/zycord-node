# Reproducible-build attestations

This directory is the substitute for a code-signing certificate, and it is not a
consolation prize.

A certificate asserts *"this came from entity X"*, backed by a certificate
authority that checked a legal identity. Zycord is published pseudonymously
and [RELEASE.md](../docs/RELEASE.md) commits it to staying that way, so no
authority will ever attest to anything about the author — and buying one would
undo the identity discipline the rest of that document is about.

A reproducible build asserts something else: *"this binary contains this source,
and anyone can check."* One person checking proves the tag is reproducible.
Several independent people checking, and signing what they got, proves that a
binary the publisher shipped is the one the source produces — which is the thing
a certificate was only ever a proxy for.

This is the pattern serious projects converged on, and the reason is the same
one that applies here: the interesting attack is not "somebody impersonated the
publisher", it is "the publisher's own build machine put something extra in the
binary". A certificate cannot see that. Six strangers rebuilding the tag can.

## What is attested, and what is not

Only `zcd` and `zycordd`. They are pure Go, `CGO_ENABLED=0`, built with
`-trimpath` and `-buildid=`, and two builds of one commit are byte-identical.
The release workflow checks that at every tag: it rebuilds `zcd` and compares
the hash against the one it is about to publish, and refuses to go on if they
differ. `make repro` is the same claim as a command anybody can run, and the
release checklist requires it before the tag exists — there is no CI that runs
it for anyone, which is why the claim is written as a command rather than as a
badge.

**The desktop wallet is not attested and cannot be.** Do not sign a claim about
it. Anyone who declines to trust a binary they cannot rebuild uses `zcd`, which
serves the same wallet interface through `zcd ui`.

The reason used to be given as "it uses cgo", and that is true of the Linux and
macOS builds — a system C toolchain and a platform SDK end up in the output and
two machines will not agree byte for byte — but it is not true of the Windows
one, which reaches WebView2 through pure Go and *is* byte-identical across
rebuilds. Nor is the second reason that was given for a while — that nothing
rebuilt the wallet and compared. Something does: `make repro-desktop` rebuilds
the Windows wallet from two other paths and compares them. A `reproducible` job
used to run the equivalent for `zcd` on every push to `main`; it is gone with the
rest of the test workflow ([RELEASE.md](../docs/RELEASE.md) §0), and the release
workflow has no `main` trigger at all. What runs it now is the release's Windows
leg, at a tag, and the release machine by hand before that.

The rule does not change with either fact, and the reason that holds on every
platform is the one to keep in mind. What a release publishes for the wallet is
a `.zip`, whose hash is not reproducible even when the binary inside it is, and
there is no `SHA256SUMS.binaries` line for the wallet to compare a rebuild
against — nor will there ever be (docs/RELEASE.md §5). A check this project runs
for itself is not a hash a stranger can hold it to. There is nothing here for an
attester to check against.

## Verifying a release

```sh
git clone <this repository> && cd zycord
git checkout v<version>

# Rebuild, on your machine, with your toolchain.
make build
sha256sum bin/zcd bin/zycordd
```

Compare against `SHA256SUMS.binaries` from the release. The Go toolchain version
matters — it is pinned in `go.mod`, and `make build` uses whatever `go` is on
your PATH, so check that `go version` matches the one the release notes name
before concluding that a mismatch means anything.

## Adding an attestation

If the hashes match, say so in a way that survives you.

1. Copy [`TEMPLATE.md`](TEMPLATE.md) to `v<version>/<your-name-or-key-id>.md`.
2. Fill in every field. An attestation with an unfilled field attests to nothing
   and is worse than none, because it looks like one.
3. Sign it with your own key: `gpg --armor --detach-sign v<version>/<name>.md`.
4. Open a pull request adding both files.

Do not sign an attestation for a build you did not perform yourself, on hardware
you control. The entire value of this directory is that the signatures are
independent; one that is not is a signature that makes the set weaker while
making it look stronger.

Attestors are welcome to be pseudonymous. What matters is that a key signs more
than one release over time, so a reader can see that the same stranger has been
checking for a year.

## The publisher's own attestation is not one of these

The release carries a build-provenance attestation, which says the bytes came
out of the project's own workflow at a named commit. That is a different claim,
it lives in the release, and it is not evidence about the build machine — it is
evidence about *ours*, made by the machine that did the building. Nothing in
this directory is produced by the publisher, and that is the entire reason it
exists: an attestation you can only get from us proves nothing you could not
already have taken on trust.
