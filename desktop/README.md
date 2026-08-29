# The desktop wallet

A native window around the frontend in [`wallet/webui`](../wallet/webui), so the
Era-0 miner the whitepaper invites to "mine on the laptop you already have" does
not need a Go toolchain to spend what they mined.

## Why this is a separate Go module

The root `go.mod` carries a promise — *"The dependency list is one module and is
meant to stay that way"* — and `make check-imports` enforces that `core/` and
`node/` are third-party-free. Wails brings cgo and a large dependency tree.

Kept apart, none of that reaches the protocol:

```sh
go list -m all                 # at the root: no Wails
make check-imports             # unchanged, still green
make build && make build       # zcd and zycordd still byte-identical
```

`go test ./...` at the root never compiles a webview, and the `reproducible` CI
job keeps checking `bin/zcd` byte for byte.

## Two tiers of assurance, stated rather than implied

| | reproducible | why |
|---|---|---|
| `zcd`, `zycordd` | **yes**, byte-identical | pure Go, `CGO_ENABLED=0`, `-trimpath`, no build id |
| `zycord-wallet`, linux and macOS | **no** | cgo: a system C toolchain and platform SDK are in the output |
| `zycord-wallet`, Windows | **yes**, the binary | no cgo: Wails reaches WebView2 through pure Go |

`docs/RELEASE.md` §5 anticipated this exactly ("`-trimpath` and a pinned Go
toolchain stop being sufficient the moment there is cgo"). Do not claim
reproducibility this binary does not have. Anyone who declines to trust a binary
they cannot rebuild uses `zcd`, which they can — that escape hatch is the point,
and it is why the CLI is a first-class interface rather than a developer tool.

## Building

```sh
cd desktop
go build -tags desktop,production -o zycord-wallet .                             # macOS
go build -tags desktop,production,webkit2_41 -o zycord-wallet .                  # Linux
CGO_ENABLED=0 go build -tags desktop,production -trimpath   -ldflags '-s -w -buildid= -H windowsgui' -o zycord-wallet.exe .                # Windows
```

The Windows line is longer than a development build needs to be, and the extra
is not decoration: it is the only command in this repository that reproduces the
released Windows binary, which `docs/INSTALL.md` now invites you to check. Three
builds of one source tree on one machine, differing only in these flags:

| command | sha256 |
|---|---|
| the line above (`CGO_ENABLED=0`, `-trimpath`) | `a2f690ba…` — matches `make dist-desktop` |
| the same with `CGO_ENABLED=1` | `45a08581…` |
| without `-trimpath` or a `CGO_ENABLED` pin | `a6f35c0c…` |

`CGO_ENABLED=1` builds fine here with no C compiler installed — the `cgo` build
tag selects different files in the dependency tree without any C being compiled —
so a machine that happens to have gcc on `PATH` gets the second row by default
and a mismatch it cannot explain. The Go patch version has to match too: 1.25.0,
1.26.0 and 1.26.6 each produce different bytes.

macOS and Linux carry no such line because those builds use cgo and are not
reproducible at all.

Windows needs `-H windowsgui`, and needs the `.exe`. `wails build` would supply
the first, and `go build -o` never supplies the second, so a plain `go build`
here produces a console-subsystem binary that Windows will not start by name and
that, once started, opens a black console window beside the wallet.

That console is not only untidy. Closing it delivers `CTRL_CLOSE_EVENT` and the
process is terminated, so `OnShutdown` -- the handler that calls `api.Lock()` and
wipes the decrypted seed -- never runs. It is a second way out of the application
that skips the one thing the application has to do on the way out.

That is the whole build. The Wails CLI is not required: the frontend has no build
step (plain HTML, CSS and JavaScript, no npm) and the assets are embedded by the
root module through `webui.Assets()`. `make dist-desktop` from the repository
root does the same thing with the release flags and, on macOS, wraps the result
in a `.app` bundle.

Platform prerequisites are the webview each system already ships:

| | |
|---|---|
| macOS | Xcode command line tools (WebKit) |
| Linux | `libgtk-3-dev`, `libwebkit2gtk-4.1-dev`, and the `webkit2_41` build tag |
| Windows | WebView2 runtime — preinstalled on Windows 11 and current Windows 10 |

The Linux build tag is not optional and the failure mode is unhelpful if it is
omitted. Wails v2.15.0 declares `#cgo !webkit2_41 pkg-config: webkit2gtk-4.0`
throughout `internal/frontend/desktop/linux/` and
`pkg/assetserver/webview/`, so an untagged build asks for the 4.0 headers —
which were dropped after Ubuntu 22.04 and are not packaged on any current
distribution. The error is a pkg-config miss for a library the machine does have
under a different version. `make dist-desktop` adds the tag on Linux by itself.

## What it does that `zcd ui` does not

Nothing, by design, except two things a browser cannot do:

- **It opens no TCP port.** `zcd ui` has to authenticate a loopback socket
  because a socket is reachable from the rest of the machine; this has nothing to
  reach. No token, no `Host` check, no CSRF surface.
- **A native file dialog**, and it remembers the choice. A web page can receive a
  file's contents but never learn its path, so the browser build asks for a typed
  path — which is what starting `zcd ui` needed anyway.

Everything else is the same file. `transport.js` picks the transport at load
time and the rest of the interface is written against neither, so the two cannot
drift into two behaviours. `bridge_test.go` reads the method names out of
`transport.js` and fails if `*Bridge` does not have them — the one contract here
that no compiler checks.

Every spend goes through `wallet/session`, so this window is structurally
incapable of being more permissive than `zcd wallet send`.

## Settings

Stored at `$XDG_CONFIG_HOME/zycord/wallet.json` (`~/Library/Application
Support/zycord/wallet.json` on macOS, `%AppData%\zycord\wallet.json` on
Windows), holding the key file path, the node address and the network. No secret
is written: a key file path is not a key, and the passphrase is never stored
anywhere.

Changing any of them locks the wallet. A key unlocked against one network must
not survive into another — addresses derive from the key rather than from a
chain, so they exist on every network and read zero on one that has never seen
them, which looks like an empty wallet rather than like a mistake.

## Known gaps

- **No application icon yet.** The window and the bundle use the platform
  default. An icon is cosmetic and was left out rather than pulled in through an
  image toolchain the build does not otherwise need.
- `link_darwin.go` names `UniformTypeIdentifiers` because Wails v2.15.0 uses
  `UTType` without linking it. Delete that file when a Wails release links it
  itself.
