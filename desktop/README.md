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

`go test ./...` at the root never compiles a webview. A `reproducible` job used
to keep checking `bin/zcd` byte for byte on every push; it is gone, and what
checks it now is the release build at a tag, plus whoever runs `make build`
twice before pushing. There is no hosted runner watching this for you.

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

Nothing, by design, except three things a browser build has no business doing:

- **It opens no TCP port.** `zcd ui` has to authenticate a loopback socket
  because a socket is reachable from the rest of the machine; this has nothing to
  reach. No token, no `Host` check, no CSRF surface.
- **Native file dialogs**, and it remembers the choice. A web page can receive a
  file's contents but never learn its path, so the browser build asks for a typed
  path — which is what starting `zcd ui` needed anyway.
- **It creates a key file.** The first-run screens are the graphical form of
  `zcd wallet new`: the person who downloaded this application has no `zcd`, and a
  wallet whose first screen asks for a file only a command line can produce has
  been unpacked rather than installed. `webui.API.Create` writes the same format,
  through the same no-clobber, no-torn-file path (`wallet.SaveKeyFile`), and
  `zcd ui` refuses the call for the same reason it refuses `Configure`: its key
  file was named on the command line.

The first run also asks which network the wallet is for — mainnet, the public
testnet or a local devnet — and offers a **Test** button that asks the node who
it is before anything is saved. A node on a different network from the one
selected is reported as exactly that, with a one-click switch, rather than as
"unreachable": the two have different fixes.

Everything else is the same file. `transport.js` picks the transport at load
time and the rest of the interface is written against neither, so the two cannot
drift into two behaviours. `bridge_test.go` reads the method names out of
`transport.js` and fails if `*Bridge` does not have them — the one contract here
that no compiler checks.

Every spend goes through `wallet/session`, so this window is structurally
incapable of being more permissive than `zcd wallet send`.

## The node beside it

The wallet is a client of a node and holds no chain of its own. Rather than
ask somebody who double-clicked an icon to also run a daemon, or point every
download at a node the project runs, the application ships a `zycordd` next
to its own executable and starts it: a full node, mining off by default, on a
data directory of its own under the configuration directory
(`<config>/zycord/node/<network>/`), with RPC on loopback. `wallet/localnode`
is the whole of that: find the binary, choose a port, start, watch, stop.

It is a **child process**, not an import. The key lives in the wallet's
memory and a node parses bytes from strangers all day; the node that ships is
`cmd/zycordd`, with the sync driver, the seeds, the checkpoints and the
shutdown order it already has; and RandomX is cgo, which the Windows wallet
deliberately is not. So `zycordd` beside the wallet is the RandomX build on
every platform — cgo, unattested, and said so in the `UNATTESTED.txt` that
travels with it — while `zycord-wallet.exe` stays pure Go and byte-identical.
`make dist-desktop` builds both; `DESKTOP_NODE=0` ships the wallet alone, and
the wallet then asks for a node to talk to.

**There is no way to name somebody else's node, and that is the design rather
than a gap.** A person opening a wallet is in no position to judge whose node
to trust, and the honest alternative to "run your own" is not "use a stranger's"
— it is a broken install, which the first-run screen says in those words when
the package has lost its zycordd. `webui.API.Configure` starts the bundled node
for the chosen network and uses the address it picked, whatever address reached
it. The only decisions a person makes are the key file, the network, and whether
this computer mines.

The node runs with no `--listen`, so it is periphery: it dials out and can never
be dialled. That needs no forwarded port, offers no inbound surface, and is a
shape the network already expects — a seed cannot tell one of these from any
other outbound-only node.

Three consequences the interface is built around:

- **Sync first.** The first launch shows a sync screen with a progress
  estimate (the tip's timestamp against the clock, since the node cannot know
  the chain's height before it has it), the peer count and the node's own log.
  Nothing claims to be in sync until the wallet has actually asked: reachable
  with the question unanswered reads "Checking sync…", because "in sync" is what
  decides whether a person believes the balance under it.
  A person can go in before it finishes; balances may then be stale and the
  wallet refuses to sign anything until the node is in sync
  (`webui.API.Sync`, checked at the top of `Send`). "In sync" is: not below the
  checkpoint floor this release enforces, a tip younger than twenty block
  intervals, and at least one peer on a public network.
- **A node that exits explains itself.** `zycordd` refuses to start on a public
  network when it was built without RandomX, and says so in one clear sentence.
  `localnode` reports that sentence as the exit reason rather than the exit
  status, because "exit status 1" is not something anybody can act on.
- **A node already running is adopted.** If something answers on 9420 and is
  on the network the wallet wants, the wallet uses it and starts nothing; if
  it is on another network, the bundled node goes to 9440.
- **Mining is a setting.** Settings → "Mine with this computer" restarts the
  bundled node with `--mine --payout <this wallet's persistent address>`. The
  node syncs first and starts on its own; on the public networks it allocates
  about 3 GiB for the RandomX dataset, which the setting says next to the box.
  The payout address is kept in the settings file (it is an address, not a
  secret) so the node can mine from launch before the key is unlocked.

The Linux and Windows wallets ask the kernel, in different words, to end the
node when the wallet dies: `Pdeathsig` on Linux, and on Windows a hidden
console. macOS has no equivalent, so a wallet that crashes there — as opposed
to one that is closed — can leave a node running until it is stopped by hand
or the machine restarts.

## Settings

Stored at `$XDG_CONFIG_HOME/zycord/wallet.json` (`~/Library/Application
Support/zycord/wallet.json` on macOS, `%AppData%\zycord\wallet.json` on
Windows), holding the key file path, the node address, the network, whether the
bundled node is used and whether it mines. No secret is written: a key file
path is not a key, a payout address is public, and the passphrase is never
stored anywhere.

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
