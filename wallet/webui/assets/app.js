/* app.js — the interface.
 *
 * Every number that came from a node is labelled as such, and every
 * irreversible act is shown in full before it happens. That is not decoration:
 * a wallet that is not itself a full node believes what a node tells it, and
 * the only honest response is to put the numbers it was told in front of the
 * person who is about to act on them.
 */

(function () {
  "use strict";

  var DROPS_PER_ZCD = 100000000n;
  var state = { wallet: null, node: null, balances: null, pending: null, settings: null };

  /* ---------- small helpers ---------- */

  function $(id) { return document.getElementById(id); }

  function show(el, on) {
    if (el) el.classList.toggle("hidden", !on);
  }

  function text(el, value) {
    if (el) el.textContent = value;
  }

  function el(tag, className, content) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (content !== undefined) node.textContent = content;
    return node;
  }

  /* Drops are u256 and ZCD has eight decimals, so every conversion here is
   * BigInt. A Number loses precision above 2^53 — which is under 100 million
   * ZCD — and a wallet that silently rounds a balance has told a lie about
   * money. */
  function dropsToZcd(drops) {
    var v = BigInt(drops);
    var whole = v / DROPS_PER_ZCD;
    var frac = (v % DROPS_PER_ZCD).toString().padStart(8, "0");
    return whole.toString() + "." + frac;
  }

  function zcdToDrops(input) {
    var s = String(input).trim();
    if (!/^\d+(\.\d{0,8})?$/.test(s)) {
      throw new Error("not an amount: " + input + " (up to eight decimals)");
    }
    var parts = s.split(".");
    var frac = (parts[1] || "").padEnd(8, "0");
    return (BigInt(parts[0]) * DROPS_PER_ZCD + BigInt(frac)).toString();
  }

  function amountToDrops(raw, unit) {
    var s = String(raw).trim();
    if (unit === "drops") {
      if (!/^\d+$/.test(s)) throw new Error("not a whole number of drops: " + raw);
      return s;
    }
    return zcdToDrops(s);
  }

  function shorten(addr) {
    if (!addr || addr.length < 20) return addr || "";
    return addr.slice(0, 10) + "…" + addr.slice(-8);
  }

  /* navigator.clipboard exists only in a secure context. http://127.0.0.1 is
   * one; the custom scheme the desktop webview serves from may not be. Copying
   * an address is not a nicety in a wallet — retyping 64 hex characters is how
   * money goes to the wrong place — so there is a fallback. */
  function copyText(value) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(value);
    }
    return new Promise(function (resolve, reject) {
      var scratch = document.createElement("textarea");
      scratch.value = value;
      scratch.setAttribute("readonly", "");
      scratch.className = "offscreen";
      document.body.appendChild(scratch);
      scratch.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      document.body.removeChild(scratch);
      ok ? resolve() : reject(new Error("the browser refused to copy"));
    });
  }

  function copyButton(value) {
    var b = el("button", "ghost copy", "Copy");
    b.addEventListener("click", function () {
      copyText(value).then(function () {
        b.textContent = "Copied";
        setTimeout(function () { b.textContent = "Copy"; }, 1200);
      }, function () {
        b.textContent = "Select and copy";
      });
    });
    return b;
  }

  function kv(pairs) {
    var dl = el("dl", "kv");
    pairs.forEach(function (p) {
      if (p[1] === undefined || p[1] === null || p[1] === "") return;
      dl.appendChild(el("dt", null, p[0]));
      dl.appendChild(el("dd", null, String(p[1])));
    });
    return dl;
  }

  /* ---------- the gate ---------- */

  function gateError(message) {
    var box = $("gate-error");
    text(box, message || "");
    show(box, !!message);
  }

  function showGate(which) {
    show($("app"), false);
    show($("gate"), true);
    show($("gate-token"), which === "token");
    show($("gate-unlock"), which === "unlock");
    show($("gate-setup"), which === "setup");
    if (which === "unlock") $("passphrase").focus();
    if (which === "token") $("token").focus();
    if (which === "setup") $("setup-key").focus();
  }

  function showApp() {
    show($("gate"), false);
    show($("app"), true);
    gateError("");
  }

  /* ---------- rendering ---------- */

  function renderHeader() {
    var w = state.wallet;
    if (!w) return;
    var badge = $("network-badge");
    text(badge, w.network + " · chain " + w.chain_id);
    badge.classList.toggle("devnet", w.network !== "zycord");
    text($("gate-keypath"), w.key_path ? w.key_path : "No key file chosen yet.");
    var rpc = w.rpc + (w.confirm_rpc ? "  ·  cross-checked against " + w.confirm_rpc : "");
    text($("footer-rpc"), "node " + rpc);
    text($("footer-mode"), Transport.mode === "desktop"
      ? "desktop build — no port is open"
      : "browser build — loopback only, token-authenticated");
  }

  function renderNode() {
    var n = state.node;
    var box = $("node");
    box.replaceChildren();
    if (!n) return;
    text($("height"), n.reachable ? "height " + n.height : "node unreachable");
    if (!n.reachable) {
      var card = el("div", "card");
      card.appendChild(el("div", "kind", "node"));
      card.appendChild(el("p", "error", n.error || "the node did not answer"));
      card.appendChild(el("p", "muted small",
        "The wallet holds no chain of its own, so nothing can be read or sent until a node answers. " +
        "Start one, or point this wallet at another with --rpc."));
      box.appendChild(card);
      return;
    }

    var chain = el("div", "card");
    chain.appendChild(el("div", "kind", "chain"));
    chain.appendChild(kv([
      ["network", n.network + " (chain id " + n.chain_id + ")"],
      ["height", n.height],
      ["tip", n.tip],
      ["state root", n.state_root],
    ]));
    box.appendChild(chain);

    var fees = el("div", "card");
    fees.appendChild(el("div", "kind", "fees and ceilings in force"));
    fees.appendChild(kv([
      ["sequential base fee", n.seq_base_fee + " drops/gas"],
      ["parallel base fee", n.par_base_fee + " drops/gas"],
      ["skip fee", n.skip_fee + " drops"],
      ["sequential target T", n.seq_gas_target],
      ["sequential ceiling", n.seq_gas_limit],
      ["parallel ceiling", n.par_gas_limit],
      ["block bytes", n.block_byte_limit],
      ["certificates per block", n.max_certs_per_block],
    ]));
    fees.appendChild(el("p", "muted small",
      "These ceilings are consensus state, not parameters: the epoch controller moves the " +
      "sequential target and the rest are derived from it."));
    box.appendChild(fees);

    var net = el("div", "card");
    net.appendChild(el("div", "kind", "network"));
    if (!n.p2p_enabled) {
      net.appendChild(el("p", "muted", "This node has no peer-to-peer network attached."));
    } else {
      net.appendChild(kv([
        ["peers", n.peers],
        ["inbound", n.inbound],
        ["outbound", n.outbound],
        ["listening", n.listening ? "yes" : "no"],
        ["reachable", n.peer_reachable ? "yes" : "no"],
      ]));
      if (n.listening && n.inbound === 0) {
        net.appendChild(el("p", "muted small",
          "Listening with no inbound connections usually means the port is not actually " +
          "reachable — the process is bound and waiting, and nothing is arriving."));
      }
    }
    box.appendChild(net);
  }

  function renderBalances() {
    var box = $("balances");
    box.replaceChildren();
    var b = state.balances;
    if (!b) return;
    b.addresses.forEach(function (a) {
      var card = el("div", "card");
      var head = el("div", "card-head");
      head.appendChild(el("span", "kind", a.kind));
      head.appendChild(el("span", "amount-sub", a.balance + " drops"));
      card.appendChild(head);
      card.appendChild(el("div", "amount", dropsToZcd(a.balance) + " ZCD"));
      card.appendChild(el("div", "addr", a.address));
      if (a.spent) {
        card.appendChild(el("div", "spent", "spent — this address can neither send nor receive"));
      }
      box.appendChild(card);
    });
    if (b.confirmed) {
      box.appendChild(el("p", "muted small",
        "Cross-checked against " + b.confirm_rpc + ", which reported the same numbers."));
    } else {
      box.appendChild(el("p", "muted small",
        "One node was asked. Start the wallet with --confirm-rpc pointed at a second, " +
        "independent node to have every balance cross-checked before an irreversible spend."));
    }
  }

  function isSpent(address) {
    if (!state.balances) return false;
    return state.balances.addresses.some(function (a) {
      return a.address === address && a.spent;
    });
  }

  function renderReceive() {
    var box = $("receive");
    box.replaceChildren();
    var w = state.wallet;
    if (!w || w.locked) return;
    [["persistent", w.persistent], ["one-shot", w.one_shot]].forEach(function (pair) {
      var card = el("div", "card");
      card.appendChild(el("div", "kind", pair[0]));
      card.appendChild(el("div", "addr", pair[1]));
      card.appendChild(copyButton(pair[1]));
      /* A burned address still derives from the key and still looks like an
       * address, so a receive screen that showed it without saying so would
       * be inviting a payment into a cell nobody can open. */
      if (isSpent(pair[1])) {
        card.appendChild(el("div", "spent",
          "spent — anything paid here is lost. Derive a new key for the next one-shot payment."));
      }
      box.appendChild(card);
    });
  }

  /* ---------- the review panel ----------
   *
   * This is the trusted display. The payee and the refund address come from
   * the form and from the key file, so nothing a node says can change them;
   * the balance is the node's word and is labelled with whose word it is. */

  function renderReview(preview, request) {
    var box = $("send-review");
    box.replaceChildren();
    box.classList.toggle("irreversible", !!preview.one_shot_drain);
    show(box, true);
    show($("send-ok"), false);

    box.appendChild(el("h3", null, preview.one_shot_drain
      ? "Review — this cannot be undone"
      : "Review"));

    box.appendChild(kv([
      ["certificate", preview.certificate],
      ["from", preview.from],
      ["to", preview.to],
      ["refund to", preview.refund],
      ["sending", dropsToZcd(preview.amount) + " ZCD  (" + preview.amount + " drops)"],
      ["fee now", preview.fee_now + " drops, of which " + preview.tip + " is the producer's tip"],
      ["reserved", preview.reserved + " drops, refunded within the same block"],
      [preview.primary_rpc + " reports the source holds", preview.held + " drops"],
      ["commits by height", preview.ttl],
    ]));

    if (preview.one_shot_drain) {
      var notice = el("div", "notice");
      notice.appendChild(el("strong", null, "A debit burns a one-shot address."));
      notice.appendChild(document.createTextNode(
        " The amount above was computed from what " + preview.primary_rpc + " says the cell holds, " +
        "and no rule in this wallet can catch a node that understated it: whatever it failed to " +
        "report is destroyed the instant this applies, with no error at any layer."));
      if (preview.confirm_rpc) {
        notice.appendChild(el("p", "small",
          preview.confirm_rpc + " was asked the same questions and gave the same answers. That is " +
          "worth exactly as much as the two being genuinely independent nodes, which this wallet " +
          "compared by URL and cannot verify."));
      } else {
        notice.appendChild(el("p", "small",
          "NOT independently confirmed — only " + preview.primary_rpc + " was asked. Consider " +
          "restarting the wallet with --confirm-rpc pointed at a second, independent node."));
      }
      box.appendChild(notice);
    }

    var actions = el("div", "review-actions");
    var cancel = el("button", "ghost", "Cancel");
    cancel.addEventListener("click", function () {
      show(box, false);
      state.pending = null;
    });
    var confirm = el("button", preview.one_shot_drain ? "danger" : "primary",
      preview.one_shot_drain ? "Burn this address and send" : "Send");
    confirm.addEventListener("click", function () {
      confirm.disabled = true;
      cancel.disabled = true;
      submit(request, preview).catch(function () {
        confirm.disabled = false;
        cancel.disabled = false;
      });
    });
    actions.appendChild(cancel);
    actions.appendChild(confirm);
    box.appendChild(actions);
  }

  /* ---------- actions ---------- */

  function sendError(message) {
    var box = $("send-error");
    text(box, message || "");
    show(box, !!message);
  }

  function buildRequest() {
    var sweep = $("send-sweep").checked;
    var req = {
      to: $("send-to").value.trim(),
      one_shot: $("send-source").value === "one-shot",
      sweep: sweep,
      amount: sweep ? "0" : amountToDrops($("send-amount").value, $("send-unit").value),
      refund: $("send-refund").value.trim(),
      headroom: Number($("send-headroom").value) || 0,
      ttl: Number($("send-ttl").value) || 0,
      seq_tip: $("send-seqtip").value.trim(),
      par_tip: $("send-partip").value.trim(),
      dry_run: true,
      approved: null,
    };
    if (!req.to) throw new Error("a recipient address is required");
    return req;
  }

  async function review(event) {
    event.preventDefault();
    sendError("");
    show($("send-review"), false);
    show($("send-ok"), false);
    var req;
    try {
      req = buildRequest();
    } catch (e) {
      sendError(e.message);
      return;
    }
    try {
      var preview = await Transport.send(req);
      state.pending = { request: req, preview: preview };
      renderReview(preview, req);
    } catch (e) {
      if (await handleAuthFailure(e)) return;
      sendError(e.message);
    }
  }

  /* The confirmation carries the numbers that were on the screen, not a bare
   * yes. The wallet process re-reads the node before it signs, so a balance
   * that moved in between produces a different certificate — and an approval
   * given for one set of numbers must not authorise another. */
  async function submit(request, preview) {
    var req = Object.assign({}, request, {
      dry_run: false,
      approved: { to: preview.to, amount: preview.amount, held: preview.held },
    });
    try {
      var result = await Transport.send(req);
      show($("send-review"), false);
      state.pending = null;
      var ok = $("send-ok");
      text(ok, "Submitted. Certificate " + result.certificate +
        " — it commits by height " + result.ttl + ", or expires.");
      show(ok, true);
      $("send-form").reset();
      await refreshBalances();
    } catch (e) {
      if (await handleAuthFailure(e)) return;
      sendError(e.message);
      throw e;
    }
  }

  /* Two failures are states rather than errors, and both can arrive in the
   * middle of any call: the idle lock fired, or the token this page holds is
   * no longer the running wallet's (it restarted, so a new one was printed).
   * Every caller routes through here so that neither ends as an unhandled
   * rejection with a window that looks fine and does nothing. */
  async function handleAuthFailure(err) {
    if (!err) return false;
    if (err.unauthorised) {
      Transport.clearToken();
      gateError("This token was refused. The wallet was probably restarted — reopen the URL it printed.");
      showGate("token");
      return true;
    }
    if (!err.locked) return false;
    state.balances = null;
    try {
      await loadWallet();
    } catch (e) {
      gateError(e.message);
      showGate("unlock");
    }
    return true;
  }

  async function loadWallet() {
    state.wallet = await Transport.wallet();
    renderHeader();
    show($("tab-settings"), state.wallet.configurable);
    if (state.wallet.needs_key) {
      /* First run of the desktop application: there is no key file to
       * unlock yet, which is a different screen from a locked one. */
      await fillSettingsForms();
      showGate("setup");
      return false;
    }
    if (state.wallet.locked) {
      showGate("unlock");
      return false;
    }
    showApp();
    renderReceive();
    return true;
  }

  async function fillSettingsForms() {
    var cfg;
    try {
      cfg = await Transport.settings();
    } catch (e) {
      return;
    }
    state.settings = cfg;
    [["setup", "gate"], ["settings", "panel"]].forEach(function (pair) {
      var p = pair[0];
      if ($(p + "-key")) $(p + "-key").value = cfg.key_path || "";
      if ($(p + "-rpc")) $(p + "-rpc").value = cfg.rpc || "http://127.0.0.1:9420";
      if ($(p + "-network")) $(p + "-network").value = cfg.network || "zycord";
      if ($(p + "-confirm")) $(p + "-confirm").value = cfg.confirm_rpc || "";
    });
    var browsable = Transport.canBrowse();
    show($("setup-browse"), browsable);
    show($("settings-browse"), browsable);
  }

  async function configure(prefix, onError) {
    var req = {
      key_path: $(prefix + "-key").value.trim(),
      rpc: $(prefix + "-rpc").value.trim(),
      network: $(prefix + "-network").value,
      confirm_rpc: $(prefix + "-confirm").value.trim(),
    };
    try {
      state.wallet = await Transport.configure(req);
      state.balances = null;
      renderHeader();
      await fillSettingsForms();
      showGate("unlock");
    } catch (e) {
      onError(e.message);
    }
  }

  async function browseForKey(prefix) {
    try {
      var path = await Transport.chooseKeyFile();
      if (path) $(prefix + "-key").value = path;
    } catch (e) {
      /* The dialog was cancelled, or the file is not a key file; the
       * wallet's own error lands on the form when Save is pressed. */
    }
  }

  async function refreshBalances() {
    try {
      state.balances = await Transport.balances();
      renderBalances();
      renderReceive();
    } catch (e) {
      if (await handleAuthFailure(e)) return;
      var box = $("balances");
      box.replaceChildren(el("p", "error", e.message));
    }
  }

  async function refreshNode() {
    try {
      state.node = await Transport.node();
      renderNode();
    } catch (e) {
      await handleAuthFailure(e);
    }
  }

  async function unlock() {
    gateError("");
    var field = $("passphrase");
    var button = $("unlock");
    button.disabled = true;
    try {
      state.wallet = await Transport.unlock(field.value);
      field.value = "";
      renderHeader();
      showApp();
      renderReceive();
      await Promise.all([refreshBalances(), refreshNode()]);
    } catch (e) {
      gateError(e.message);
    } finally {
      button.disabled = false;
    }
  }

  async function lock() {
    try {
      state.wallet = await Transport.lock();
      state.balances = null;
      renderHeader();
      showGate("unlock");
    } catch (e) {
      if (await handleAuthFailure(e)) return;
      gateError(e.message);
      showGate("unlock");
    }
  }

  /* ---------- wiring ---------- */

  function wire() {
    document.querySelectorAll(".tab").forEach(function (tab) {
      tab.addEventListener("click", function () {
        document.querySelectorAll(".tab").forEach(function (t) { t.classList.remove("active"); });
        document.querySelectorAll(".panel").forEach(function (p) { p.classList.add("hidden"); });
        tab.classList.add("active");
        show($(tab.dataset.panel), true);
        if (tab.dataset.panel === "panel-node") refreshNode();
        if (tab.dataset.panel === "panel-balance") refreshBalances();
        if (tab.dataset.panel === "panel-settings") fillSettingsForms();
      });
    });

    $("send-form").addEventListener("submit", review);
    $("refresh-balance").addEventListener("click", refreshBalances);
    $("refresh-node").addEventListener("click", refreshNode);
    $("lock").addEventListener("click", lock);
    $("gate-unlock").addEventListener("submit", function (e) {
      e.preventDefault();
      unlock();
    });
    $("gate-token").addEventListener("submit", function (e) {
      e.preventDefault();
      start();
    });
    $("gate-setup").addEventListener("submit", function (e) {
      e.preventDefault();
      configure("setup", gateError);
    });
    $("settings-form").addEventListener("submit", function (e) {
      e.preventDefault();
      configure("settings", function (message) {
        var box = $("settings-error");
        text(box, message);
        show(box, true);
      });
    });
    $("setup-browse").addEventListener("click", function () { browseForKey("setup"); });
    $("settings-browse").addEventListener("click", function () { browseForKey("settings"); });

    var sweep = $("send-sweep");
    sweep.addEventListener("change", function () {
      $("send-amount").disabled = sweep.checked;
      if (sweep.checked) $("send-amount").value = "";
    });
    $("send-source").addEventListener("change", function () {
      /* Spending a one-shot address at all empties it, so the only amount it
       * can send is its whole balance. Setting the box rather than hiding it
       * keeps the reason visible. */
      if ($("send-source").value === "one-shot") {
        sweep.checked = true;
        sweep.dispatchEvent(new Event("change"));
      }
    });
  }

  async function start() {
    if (Transport.mode === "browser") {
      var typed = $("token").value.trim();
      if (typed) Transport.setToken(typed);
      /* A handoff that would not exchange is reported whatever else this tab
       * has, and before anything else can overwrite the message.
       *
       * The benign reading is that the browser was slow or the tab was
       * reopened. The one that matters is that something else on this machine
       * spent the handoff first — and that case is not conditional on this tab
       * having no token. A stale token in sessionStorage from an earlier run
       * would otherwise carry us past this check, 401 on the first call, and
       * get explained away as "the wallet was probably restarted": the benign
       * message, shown for the one situation that is not benign. */
      if (Transport.handoffError) {
        gateError(Transport.handoffError);
        Transport.clearToken();
        showGate("token");
        return;
      }
      if (!Transport.hasToken()) {
        showGate("token");
        return;
      }
    }
    try {
      var unlocked = await loadWallet();
      if (unlocked) {
        await Promise.all([refreshBalances(), refreshNode()]);
      } else {
        /* Even locked, the header should say which network and which node,
         * so a wrong --devnet is visible before a passphrase is typed. */
        await refreshNode();
      }
    } catch (e) {
      if (await handleAuthFailure(e)) return;
      gateError(e.message);
      showGate(Transport.hasToken() ? "unlock" : "token");
    }
  }

  async function boot() {
    wire();
    await Transport.init();
    await start();
    /* A slow poll for the header's height and the node panel. Balances are
     * refreshed on demand and after a send, not on a timer: a wallet that
     * polls a balance every few seconds is a wallet that has told the node
     * operator which addresses it cares about, over and over. */
    setInterval(refreshNode, 15000);
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
