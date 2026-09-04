# Zycord — Implementation Findings I8: the service surface

**Scope:** everything that parses input from outside the peer-to-peer layer — the Stratum
endpoint (`node/stratum`, landed today, one prior review), the JSON-RPC (`node/rpc`), the
wallet (`wallet/`, `cmd/zcd`), and the wiring that exposes them.

**Persona:** the stranger with a socket. I1 read the spec literally; I5 audited its
instruments; I7 found a build that was lying. This pass asks a narrower question of every
surface: *what can somebody who has been given nothing but a TCP connection make this node
do?* Not "is the code correct" — it is, very largely, and the Stratum package is the most
carefully commented thing in this tree — but "which of its stated bounds survive contact
with a peer that is not a miner".

The answer is that the Stratum bounds hold up well and the one that was claimed loudest
was claimed on a test that could not fail. And that the sharpest finding in this pass is
not in the new code at all: it is in the RPC, which has been loopback-bound and considered
safe since M1, and which a web page can write to.

---

## CRITICAL

### I8-C1 — Any page the operator visits can write to the mempool and to the network ✅ *fixed*

`node/rpc` has, until this pass, rested on one sentence: it is bound to loopback and
read-only except for submission. Both halves are true. Neither is the property that
matters, because **a loopback bind is not a defence against a browser.**

The same-origin policy prevents a page *reading* a cross-origin reply. It does not prevent
it *sending* the request. A `POST` carrying `Content-Type: text/plain` is a CORS **simple
request**: it goes out with no preflight, so there is no permission to deny. Any page the
operator has open — an advertisement, a documentation site, anything — can therefore post
to `127.0.0.1:9420`.

Demonstrated end to end, with a real signed certificate built by `wallet.Builder`, in
`node/rpc/rebinding_test.go`:

```
POST /submit
Host: rebound.attacker.example
Origin: https://attacker.example
Sec-Fetch-Site: cross-site
Content-Type: text/plain;charset=UTF-8

→ 200 {"accepted":true,"id":"0x0394d0…"}
   mempool size = 1
   AnnounceCertificate fired: relayed to 1 peer
```

The last line is what makes this critical rather than a local nuisance. `handleSubmit`
gossips on admission, so **the write does not stay on the operator's machine.** A page in
a browser reaches the peer-to-peer network through a node that was never exposed.

With DNS rebinding — a name the attacker controls, re-resolved to `127.0.0.1` after their
page has loaded — the page's own origin *becomes* loopback and the replies become
readable too, which turns every read route into an enumeration of the operator's
addresses and balances. `/balance`, `/cell` and `/network` all answered a cross-site
request before this fix.

**None of this is a novel attack, and this tree already knew it.** `docs/RUNNING.md` names
DNS rebinding as "the real attack against a server on loopback", and
`wallet/webui/server.go` carries exactly the guard for it — a `loopbackHost(r.Host)` check
on every route, with a `Sec-Fetch-Site`/`Origin` check on writes, and a comment explaining
why the port is deliberately not compared. The node's RPC carried neither. **The
asymmetry was the defect, not the reasoning**: nothing about a node makes it a less
interesting target than a wallet, and the node is the one that can talk to peers.

**Fixed** with `guardHost` in `node/rpc/rpc.go`: every route refuses a request whose
`Host` is not a loopback name, 403 with a body naming the cause.

The instrument choice is worth recording, because the obvious one is wrong. **`Origin` is
not the right header here.** This RPC's clients are `curl`, `zcd` and monitoring, none of
which send `Origin` at all, so requiring one would refuse every legitimate caller — which
is precisely why `wallet/webui` can demand it and this cannot. `Host` refuses none of
them: `curl` sends `Host: 127.0.0.1:9420` because that is the address it was given, while
a browser reports the name it was navigated to and cannot forge that name into a loopback
one without giving up the rebinding. The port is not compared, for `wallet/webui`'s
stated reason: the attacker must already use our port for the request to arrive, and
ignoring it keeps `ssh -L 9999:127.0.0.1:9420` working.

**Why the existing suite did not catch it.** `TestSubmitIsTheOnlyWriteAndGrantsNothing`
asks whether submission grants *authority* and answers, correctly, no: a certificate is
held to exactly the rules a peer's would face, and an unfunded one is refused. That is a
good question and a real property. It is simply a different question from **who can reach
the socket**, and nothing in the package asked that one. The lesson generalises past this
finding: *"this endpoint grants no privilege" and "this endpoint is not reachable by an
attacker" are independent claims, and a surface needs both.*

**Mutation-checked.** Disabling the guard fails `TestASubmitFromAForeignOriginIsRefused`,
`TestAReadFromAForeignOriginIsRefused`, and — deliberately — the rewritten wiring test
`TestTheServerNewBuildsIsRoutedToThisPackagesMux`, which now asserts the guard is in the
*served* path rather than only that routing resolves.

⚠ **One consequence for operators, stated plainly.** A reverse proxy in front of the RPC
must now set `Host: 127.0.0.1`. `docs/RUNNING.md` already advises rate-limiting at a proxy
if the RPC is exposed at all; that advice now carries a requirement. An unproxied RPC on
a routable address is refused outright, which is the configuration this guard should be
refusing.

---

## HIGH

### I8-H1 — `getjob` is unscored, unrated, and assembled a template per call ✅ *fixed*

`onGetJob`'s comment priced the method: *"The cost is one Assemble, which is bounded by
how often a miner can ask, which is bounded by the ban score and the connection cap."*

Every clause is true except the bound. `getjob` is **deliberately unscored** — a miner
asking for work is behaving, and scoring it would ban miners for the method's honest use —
so the ban score never fires on this path, and the connection cap bounds the number of
askers rather than the rate any one of them asks at. Measured, a single pipelined
connection issues about **16,500 getjob calls a second**.

What each one bought, against a real chain rather than the package's fake assembler: a
chain snapshot, a walk of the difficulty window, a mempool selection, a **dry-run fold to
a fixpoint** over the selected certificates, a `CertRoot`, and at an epoch boundary a full
`SealStateRoot`. `BenchmarkAssembleIsWhatAGetjobCosts` (added, `node/miner`) prices it at
**~570 µs** on an idle devnet.

So one connection asked for roughly **nine CPU-seconds of work per wall-clock second**,
and `TestGetJobFloodAgainstARealChain` measured the default sixteen of them slowing the
node's own template assembly by **45×** — on a node whose entire purpose at that moment is
to assemble templates for the miner it is serving.

**Fixed** with `minAssemblyInterval` (one second) in `node/stratum/conn.go`: a `getjob`
inside the interval is answered from the connection's newest cached job.

Served from cache rather than refused or scored, and the choice is the finding's real
content. Refusing breaks the method's honest use — a miner that has exhausted a nonce
space needs work *now*. Scoring bans miners for asking. A cached job is a **correct**
answer to "give me work": it is the same template the miner would have been pushed, its
nonce space is untouched, and a miner that genuinely exhausted 2^32 nonces inside one
second does not exist. The honest caller is unaffected; the flood buys nothing. The
interval is stamped in `newJob`, so a push or a login counts against it too — a `getjob`
arriving just after a pushed job was built is asking for a template that already exists.

After the fix the same 3,000-call flood buys **zero** assemblies.

⚠ **What the fix does not remove, measured rather than assumed.** The end-to-end
wall-clock ratio is still ~19–37×, and it would be dishonest to file that as solved. A
CPU profile of the flood after the fix puts **36% of the process in syscalls** and most of
the remainder in `encoding/json`, with blake3 at 2%: the residual is the socket and the
JSON, which is the ordinary cost of serving a client that sends as fast as it can, and is
a class of work every network service pays. It is bounded by the connection cap and it is
two orders of magnitude cheaper per unit than the assembly it replaced. The e2e test
therefore asserts the **assembly** bound and records the wall-clock figure as a
measurement, because a ratio assertion there would be asserting the speed of the Go
poller on whichever machine CI happened to use.

**A pool operator exposing this endpoint should still rate-limit in front of it.** That
was true before and remains true; what changed is that the expensive thing behind the
socket is no longer reachable at line rate.

---

## MEDIUM

### I8-M1 — A nonce was remembered before it was shown to be worth remembering ✅ *fixed*

`job.submitted`'s comment states its own bound:

> It is bounded implicitly by the job cache's own size: a job leaves the cache after
> `jobCacheSize` newer jobs, so an attacker who wanted this map to grow would have to
> spend a real hash per entry to get past the low-difficulty check first — and a share
> that passes that check is a share worth remembering.

That describes an insert placed **after** the target check. The insert was **before** it:
`onSubmit` wrote `j.submitted[nonce] = struct{}{}` while still holding the lock for the
duplicate lookup, several dozen lines above `meetsJobTarget`. Three thousand shares that
could never meet the target produced three thousand entries
(`TestOnlyASharePassingTheTargetIsRemembered`).

**This is not the memory bomb it first looks like, and saying so is part of the finding.**
The shipped ban score closes a connection after five bad shares, so the map cannot grow
past a handful of entries per job per connection; `TestUnderTheShippedScoreTheNonceMapIsSmall`
pins that. The comment was wrong about the mechanism while a *different* mechanism
happened to hold the bound.

The reason it is worth moving rather than only re-documenting is the second-order effect,
which the ban score does not cover. Because a failed nonce was recorded, **the second
submission of a nonce that had already failed the target was answered as a duplicate — one
point — instead of as a bad share, which is two.** A flooder halved its own score cost by
repeating itself, doubling the requests it gets before disconnection.

**Fixed:** the insert moved below `meetsJobTarget`. A repeat of a refused nonce is now
refused again at full price, and the map holds only shares that cost their sender a real
proof of work — which is what the comment always claimed.

Mutation-checked in both directions: restoring the original ordering fails all three of
`TestTheSubmittedNonceMapCannotBeGrownForFree`,
`TestOnlyASharePassingTheTargetIsRemembered` and
`TestRepeatingABadNonceIsNoCheaperThanSendingANewOne`.

### I8-M2 — The nicehash-nonce test could not fail ⚠ *third vacuous test in this tree*

The constraint is real and the code that enforces it is correct. **The test that guards it
asserted nothing.**

A served blob whose nonce field is non-zero latches stock XMRig into nicehash mode,
permanently narrowing that connection's search to 24 bits, and nothing in the protocol
reports it — a healthy-looking hashrate finding 256× fewer shares. `blobFor` clears those
four bytes at run time, and its comment is emphatic about *why* it is enforced at run time
rather than only asserted in a test:

> The invariant depends on a caller handing this a freshly assembled header, which is a
> property of code elsewhere that nothing otherwise stops changing.

`TestTheServedBlobShipsAZeroNonce` is that test, and its own comment says it exists because
the nonce "is zero today because `newJob` builds its blob from a freshly assembled header,
which is a property of code somewhere else that nothing otherwise stops changing". But it
drives the endpoint through the package's **fake assembler**, which produces a header whose
nonce is already zero. So it asserted precisely the precondition it declared it was not
relying on.

**Deleting the entire nonce-clearing loop from `blobFor` leaves it green**, verified in
isolation with `-count=1`.

**Fixed** by `TestNoServedBlobEverCarriesADirtyNonce`, which gives the fake assembler a
dirty nonce (`0xdeadbeef`) and an ExtraNonce, then reads the blob off the wire on all
three paths that serve one — the login reply, a `getjob`, and a pushed `job` notification.
It fails on the mutation, at the right byte, with the consequence in the message.

**This is the third vacuous test this repository has shipped** (I5 found four instruments
measuring nothing; I7 found a suite not compiling the code under test), and it was found
the same way all of them were: by mutating rather than by reading. The shape here is worth
naming because it is subtler than the earlier two and it will recur — **a test whose
fixture cannot express the failure it is guarding against.** The assertion was right, the
harness was incapable of violating it, and no amount of reading the test finds that. The
question I5 taught, asked of a fixture rather than of an instrument: *what would this test
look like if the code under it were deleted?*

The constraint itself is **confirmed intact** on every path.

---

## LOW / NOTES

- **I8-L1 — The `login` address goes straight into `EmissionAddr`, and that is exactly as
  exposed as the package says.** ✅ *reasoning tested, and it holds.* The brief asked me to
  test the no-authentication reasoning rather than accept it, so:
  `TestAnyConnectionSteersTheEmissionAddress` drives an unauthenticated connection that
  names an attacker's address, submits, and asserts the applied block's `EmissionAddr` is
  the attacker's. It is. The package comment's claim — *"an attacker who can connect can
  mine to their own address using your electricity — and no protocol-level secret fixes
  it"* — is correct, and the conclusion drawn from it is the right one. A password would
  not help: it would be a shared secret in a miner config file on every machine in the
  room, and it would make the socket *read* safe to expose while leaving the emission
  address just as steerable by anyone who reads that config. **The reasoning survives the
  test.** What matters operationally is the bind, and the wiring's non-loopback warning is
  loud, unconditional, and not behind a `--i-know-what-im-doing` flag. That is the right
  design.
- **I8-L2 — The "listening" line named an algorithm the endpoint does not serve.** ✅
  *fixed.* `cmd/zycordd` printed `stratum listening on … (rx/0, solo …)` as a constant,
  while `algoFor` resolves the running engine to `rx/2`. This is the same defect
  `algoFor`'s own comment records an earlier revision shipping *into the protocol*, where
  it refused every correctly configured stock miner — it had survived in the log, on the
  one line an operator reads while bringing a network up. The line now asks the endpoint,
  which asks the engine (`Server.Algo`).
- **I8-L3 — A `login` whose `params` is JSON `null` succeeds.** ⚠ *accepted.*
  `json.Unmarshal` of `null` into a struct leaves it zero, so `Login` is empty and
  `resolvePayout` takes the documented fallback to the node's `--payout`. The outcome is
  identical to `{"login":""}`, which is a login this endpoint deliberately accepts, so
  there is nothing to refuse. Recorded because it looks like a parser gap and is not.
- **I8-L4 — The keepalive reaper, the connection cap and the 4 KiB line cap are all real.**
  ✅ *verified by mutation, not by reading.* Disabling the reaper's comparison fails four
  tests including two new ones; removing the cap check fails
  `TestTheConnectionCapIsEnforced`; raising the line cap to 64 MiB fails both the existing
  oversize test and the new byte-at-a-time one. Two attacker-side properties are newly
  pinned: a connection that logs in and then **stops reading** is still reaped
  (`TestASilentNonReaderIsStillReaped` — the reaper shares a goroutine with the job push,
  which can block on the write deadline, so this was not obvious), and sixteen silent
  sockets that never authenticate cannot hold every slot forever
  (`TestSilentSocketsCannotStarveTheEndpointForever`).
- **I8-L5 — The share path never asks for a fast RandomX representation, on any path.** ✅
  The package holds a `pow.Engine`, never type-asserts to `pow.HotKeyEngine`, and reaches
  the work function only through `pow.CheckWork` and `recoverPoWHash`, neither of which can
  request one. The existing `hotSpy` test asserts the negative and is **not** vacuous — it
  counts `MineOn` calls against a spy that implements the interface. A ~2 GiB dataset
  cannot be built from the network here.
- **I8-L6 — The unscored paths cost no hash.** ✅ Two thousand submits naming a job id the
  cache does not hold cost **zero** engine evaluations
  (`TestTheFreeStalePathCostsNoHashes`): the cache miss is answered before any
  reconstruction. The cheap-refusals-first ordering `onSubmit`'s comment describes is real,
  and the free stale path is free to the node as well as to the miner.
- **I8-L7 — Malformed input does not panic.** ✅ Twenty malformed frames — wrong param
  types at every position, `params` as an array/string/number/null, `method` as a number,
  bare `[]`/`null`/`{}`, ids as objects and arrays and floats and a value past 2^64 — leave
  the endpoint answering and the accept loop alive. Ids are echoed byte-identically,
  including duplicates and `null`, which is what the dialect requires. Unterminated frames,
  byte-at-a-time writes past the cap, and embedded NULs are all bounded. No race under
  `-race` with eight connections submitting while `OnHead` pushes.
- **I8-L8 — The wallet's key and passphrase handling is sound, and the passphrase claim
  holds.** ✅ A passphrase reaches no environment variable, no argv, no systemd unit, no log
  line and no error message; it is read with `term.ReadPassword` and there is no
  `--passphrase` flag. Key files are `0600` from creation — `os.CreateTemp` opens at 0600,
  so there is no 0644-then-`chmod` window — and the destination check uses `Lstat`, so a
  dangling symlink counts as occupied. Argon2id at t=3/m=64 MiB/p=4 with a fresh 16-byte
  random salt, under AES-256-GCM, so a tampered keyfile fails closed rather than yielding a
  silent wrong key. `zcd ui` hands the browser a single-use handoff rather than the session
  token, specifically because argv is world-readable. Two notes rather than findings:
  `Key.Seed()` returns an escaping copy that `Zero()` cannot reach — every production
  caller zeroes its own copy, but `key_zero_test.go` would not catch a future one that
  does not — and nothing `mlock`s, so a seed can reach swap or a core dump, which
  `wallet/key.go` already records as an accepted limit.
- **I8-L9 — The RPC is read-only apart from `/submit`, as claimed.** ✅ Eleven routes,
  ten `GET`/`HEAD`-only behind a verb check that runs before the limiter. No reorg trigger,
  no peer control, no config write, no miner control, no shutdown, no file write, and no
  route that returns key material — the node holds none. Submission is cost-ordered
  correctly: `mempool.Add` runs structural validity and the O(1) screens first and pays for
  Ed25519 verification **last**, with the `screened` token kept as a compiler-checked proof
  that the order cannot be inverted. Body cap 1 MiB, 600 req/min, a 256 MiB/min block-byte
  budget, and no `Content-Encoding` handling anywhere, so there is no decompression bomb.
- **I8-L10 — `--rpc` accepts a routable address with no validation and no warning.** ⚠
  *open.* The default is loopback, so the claim holds by default. But the Stratum endpoint
  validates its own bind and warns loudly when it is not loopback, and the RPC — the older
  surface, and the one I8-C1 shows is more reachable than it looked — prints nothing.
  I8-C1's `Host` guard now refuses a browser regardless of the bind, which is the important
  half; the missing warning is still an asymmetry worth closing, and it is one line beside
  the one that already exists for Stratum.

---

## Confidence

- **I8-C1** is the finding I am most confident in, and the concern worth naming is the
  fix's blast radius rather than the defect: the `Host` check touches every RPC client.
  **Measured rather than assumed**, since this is exactly the kind of thing an audit should
  not take on trust: Go's `http.Client` sets `Host` from the request URL, so a client
  pointed at `http://127.0.0.1:9420` sends `Host: 127.0.0.1:9420` and one pointed at
  `localhost` sends `Host: localhost:9420` — both accepted. That covers what this tree
  ships: `cmd/zcd` defaults `--rpc` to `http://127.0.0.1:9420`, `wallet/localnode` builds
  its URL from `127.0.0.1` literally, and `wallet/session`'s client is constructed from
  that same base. **What the check does refuse is a reverse proxy that rewrites `Host` to
  the public name**, which is a configuration `docs/RUNNING.md` already advises against
  running unproxied and which now needs one directive (`proxy_set_header Host
  127.0.0.1;`). A deployment already proxying this way is the one thing to confirm before
  the freeze, and it is an operator question rather than a code one.
- **I8-H1's residual** is where I am least satisfied. The assembly bound is solid and
  mutation-checked; the remaining wall-clock cost is real, is socket-and-JSON rather than
  consensus work, and is bounded only by the connection cap. I have priced it and declined
  to assert a ratio on it. Whether sixteen connections at line rate is acceptable for a
  pool operator is an operational question I cannot settle from here, and the honest answer
  is "rate-limit in front of it", which was already the advice.
- **I8-M2** I am confident is vacuous and confident the replacement is not, because I ran
  both against the same deletion in isolation. What I cannot claim is that the rest of the
  Stratum suite is free of the same shape; I mutation-tested the four bounds the brief
  named and the nonce invariant, not all thirty-nine tests. **The fixture-cannot-express-
  the-failure shape is worth a dedicated pass over this package before the freeze**, and
  it is the single highest-value thing left undone on this surface.
- **Not reached.** I did not audit `wallet/session` spend logic or `wallet/policy.go` in
  depth, nor `desktop/`, nor the update path's signature verification (`cmd/zcd/update.go`)
  — that last one is a genuine external-input surface and it is unexamined here. I did not
  test the RPC under connection exhaustion: there is no `MaxConns` on that listener, which
  is irrelevant while it is loopback-bound and is not irrelevant if I8-L10 is ever
  exercised.

**Disposition.** I8-C1, I8-H1, I8-M1, I8-M2 and I8-L2 are fixed, each with a test that
fails against the unfixed code. I8-L3 is accepted and recorded. I8-L10 is open and small.
The Stratum endpoint's stated bounds — the cap, the score, the line limit, the keepalive,
the light-mode verification, and the zero nonce — are all real; one of them was being
guarded by a test that could not fail, and that is the finding this surface contributes to
the line.
