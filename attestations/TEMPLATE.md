# Attestation: zycord v<VERSION>

I rebuilt the tag below from source on hardware I control, and the binaries I
got are byte-identical to the ones the release publishes.

| | |
|---|---|
| Release tag | `v<VERSION>` |
| Commit | `<full 40-character sha>` |
| Date (UTC) | `<YYYY-MM-DD>` |
| Go toolchain | `<output of: go version>` |
| Host OS / arch | `<e.g. linux/amd64, Debian 12>` |
| Attestor | `<name or pseudonym>` |
| Key fingerprint | `<full fingerprint, no spaces omitted>` |

## What I ran

```sh
git clone <repository> zycord && cd zycord
git checkout v<VERSION>
git rev-parse HEAD          # must equal the commit above
make build
sha256sum bin/zcd bin/zycordd
```

## What I got

```
<sha256>  bin/zcd
<sha256>  bin/zycordd
```

## What the release publishes

```
<the matching lines from SHA256SUMS.binaries, for this platform>
```

## Scope

This attests to `zcd` and `zycordd` for the platform named above, and to
nothing else. In particular it does not attest to the desktop wallet — see
`attestations/README.md` for why, on every platform and not only the ones that
use cgo — and it does not attest that the source is correct, only that the
published binary is what this source produces.

## Anything that did not match, or that I want on the record

<Delete this section if there was nothing. If a hash did not match, say so here
and do not sign the attestation as a success — a mismatch is the single most
valuable thing this directory can record.>
