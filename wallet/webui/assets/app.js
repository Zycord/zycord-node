/* app.js — the interface.
 *
 * Every number that came from a node is labelled as such, and every
 * irreversible act is shown in full before it happens. That is not decoration:
 * a wallet that is not itself a full node believes what a node tells it, and
 * the only honest response is to put the numbers it was told in front of the
 * person who is about to act on them.
 *
 * The file is in four parts: helpers, the gate (everything before the key is
 * in memory, including the first-run screens), the wallet panels, and the
 * wiring that connects buttons to the two.
 */

(function () {
  "use strict";

  var DROPS_PER_ZCD = 100000000n;
  var state = {
    wallet: null,     // WalletState, from the last call that returned one
    node: null,       // NodeInfo, from the last poll
    balances: null,   // Balances, refreshed on demand and after a send
    settings: null,   // ConfigureRequest, what the forms are filled from
    networks: null,   // NetworkInfo[], fetched once
    pending: null,    // the preview a person is looking at
    wizard: null,     // "create" or "open" while the first-run screens run
    sync: null,       // SyncInfo, from the last poll
    local: null,      // localnode.Info, from the last poll
    syncSkipped: false, // the person chose to go in before the node caught up
  };

  /* ---------- helpers ---------- */

  function $(id) { return document.getElementById(id); }

  function show(elm, on) {
    if (elm) elm.classList.toggle("hidden", !on);
  }

  function text(elm, value) {
    if (elm) elm.textContent = value;
  }

  function el(tag, className, content) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (content !== undefined) node.textContent = content;
    return node;
  }

  /* A button that is waiting on the wallet says so, and cannot be pressed
   * twice. Pressing "Send" twice is the failure mode this exists for. */
  function busy(button, on) {
    if (!button) return;
    button.disabled = !!on;
    button.classList.toggle("busy", !!on);
  }

  var toastTimer = null;
  function toast(message, kind) {
    var box = $("toast");
    text(box, message);
    box.className = "toast" + (kind ? " " + kind : "");
    show(box, true);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { show(box, false); }, 2200);
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

  /* For display: thousands separators on the whole part, trailing zeros
   * trimmed to at least two decimals. The exact figure in drops is always
   * shown beside it somewhere, so nothing is lost. */
  function formatZcd(drops) {
    var s = dropsToZcd(drops);
    var parts = s.split(".");
    var whole = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    var frac = parts[1].replace(/0+$/, "");
    if (frac.length < 2) frac = (frac + "00").slice(0, 2);
    return whole + "." + frac;
  }

  function formatDrops(drops) {
    return BigInt(drops).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  }

  function zcdToDrops(input) {
    var s = String(input).trim().replace(/,/g, "");
    if (!/^\d+(\.\d{0,8})?$/.test(s)) {
      throw new Error("Not an amount: \"" + input + "\". Use digits, with up to eight decimals.");
    }
    var parts = s.split(".");
    var frac = (parts[1] || "").padEnd(8, "0");
    return (BigInt(parts[0]) * DROPS_PER_ZCD + BigInt(frac)).toString();
  }

  function amountToDrops(raw, unit) {
    var s = String(raw).trim().replace(/,/g, "");
    if (unit === "drops") {
      if (!/^\d+$/.test(s)) throw new Error("Not a whole number of drops: \"" + raw + "\".");
      return s;
    }
    return zcdToDrops(s);
  }

  function isAddress(s) {
    return /^0x0[12][0-9a-fA-F]{62}$/.test(s);
  }

  function shorten(addr) {
    if (!addr || addr.length < 20) return addr || "";
    return addr.slice(0, 8) + "…" + addr.slice(-6);
  }

  function kindLabel(kind) {
    return kind === "one-shot" ? "One-shot address" : "Persistent address";
  }

  function networkLabel(name) {
    var list = state.networks || [];
    for (var i = 0; i < list.length; i++) {
      if (list[i].name === name) return list[i].label;
    }
    return name || "—";
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

  function copyButton(value, label) {
    var b = el("button", "ghost copy", label || "Copy");
    b.type = "button";
    b.addEventListener("click", function () {
      copyText(value).then(function () {
        toast("Copied to the clipboard");
      }, function () {
        toast("Could not copy — select the text and copy it by hand", "bad");
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

  /* Every screen the gate can show, named literally so that the test pinning
   * element ids to index.html sees each one. */
  function gateScreens() {
    return {
      token: $("gate-token"), welcome: $("gate-welcome"), setup: $("gate-setup"),
      create: $("gate-create"), open: $("gate-open"), done: $("gate-done"), unlock: $("gate-unlock"),
      sync: $("gate-sync"),
    };
  }

  function gateError(message) {
    var box = $("gate-error");
    text(box, message || "");
    show(box, !!message);
  }

  function showGate(which) {
    show($("app"), false);
    show($("gate"), true);
    var screens = gateScreens();
    Object.keys(screens).forEach(function (name) {
      show(screens[name], name === which);
    });
    gateError("");
    var focus = {
      token: "token", unlock: "passphrase", create: "create-key", open: "open-key",
    }[which];
    if (focus && $(focus)) $(focus).focus();
  }

  function showApp() {
    show($("gate"), false);
    show($("app"), true);
    gateError("");
  }

  /* ---------- chrome: the parts of the page that say where we are ---------- */

  function renderChrome() {
    var w = state.wallet;
    if (!w) return;
    var badge = $("network-badge");
    text(badge, networkLabel(w.network));
    badge.className = "badge" + (w.network === "zycord" ? "" : " " + (w.network.indexOf("test") >= 0 ? "testnet" : "devnet"));
    text($("gate-sub"), "Wallet · " + networkLabel(w.network));
    text($("gate-keypath"), w.key_path || "");
    var rpc = w.rpc + (w.confirm_rpc ? "  ·  cross-checked against " + w.confirm_rpc : "");
    text($("foot-node"), "Node " + rpc);
    text($("foot-build"), Transport.mode === "desktop"
      ? "Desktop build — no network port is open"
      : "Browser build — loopback only, token-authenticated");
    var v = w.version ? "wallet " + w.version : "";
    if (w.node_version) v += (v ? " · " : "") + "node " + w.node_version;
    text($("foot-version"), v);
    text($("gate-version"), v);
    show($("tab-settings"), !!w.configurable);
    show($("unlock-switch"), !!w.configurable);
    show($("settings-switch"), !!w.configurable);
  }

  /* The node pill is the one thing that is on every screen, because "is
   * anything listening" is the question behind most confusion: this wallet
   * never syncs, so a blank screen is never "still syncing" — it is a node
   * that did not answer. */
  /* True for the graphical wallet, which runs its own node; false under
   * `zcd ui`, which was handed a node on a command line. */
  function isLocalMode() {
    return !!(state.wallet && state.wallet.node_mode === "local");
  }

  function localStarting() {
    return isLocalMode() && state.local && (state.local.running || state.local.adopted);
  }

  function renderStatusPill() {
    var n = state.node;
    var sy = state.sync;
    var cls, label;
    if (!n) {
      cls = ""; label = "Checking node…";
    } else if (n.reachable && sy && sy.syncing) {
      cls = "warn";
      label = sy.no_peers && !sy.stale && !sy.behind_floor ? "Looking for peers"
        : "Syncing · " + Math.floor(sy.progress) + "%";
    } else if (n.reachable && sy) {
      cls = "ok"; label = "In sync · height " + n.height;
    } else if (n.reachable) {
      /* Reachable, and nothing has answered the question this pill exists to
       * answer. "In sync" is the one claim that must never come out of
       * missing information: it is what decides whether a person believes the
       * balance under it. */
      cls = ""; label = "Checking sync…";
    } else if (n.mismatch) {
      cls = "warn"; label = "Node is on " + networkLabel(n.node_network);
    } else if (localStarting()) {
      cls = "warn"; label = "Starting node…";
    } else {
      cls = "bad"; label = "No node";
    }
    [$("node-pill"), $("gate-status")].forEach(function (pill) {
      pill.className = "status-pill " + cls;
      text(pill, label);
    });
  }

  /* One explanation of the node's state, used by the overview and the node
   * panel. Returns null when there is nothing to explain. */
  function nodeCallout() {
    var n = state.node;
    var w = state.wallet || {};
    var sy = state.sync;
    if (!n) return null;
    if (n.reachable && !(sy && sy.syncing)) return null;
    var settling = n.reachable || n.mismatch || localStarting();
    var card = el("div", "card callout " + (settling ? "warn" : "bad"));
    var body = el("div");
    if (n.reachable) {
      body.appendChild(el("h3", null, sy.no_peers && !sy.stale && !sy.behind_floor
        ? "The node is looking for peers" : "The node is still syncing"));
      body.appendChild(el("p", null, sy.message + ". Balances shown now may be stale, and nothing " +
        "is sent until the node has caught up."));
      body.appendChild(el("p", "small mono muted", "height " + n.height + " · " + sy.peers + " peers"));
    } else if (n.mismatch) {
      body.appendChild(el("h3", null, "The node is on a different network"));
      body.appendChild(el("p", null,
        w.rpc + " says it is on " + networkLabel(n.node_network) + " (chain id " + n.node_chain_id +
        "), but this wallet is set to " + networkLabel(w.network) + " (chain id " + w.chain_id + "). " +
        "Nothing is read from a node on the wrong network."));
      var actions = el("div", "actions");
      var sw = el("button", "primary", "Switch this wallet to " + networkLabel(n.node_network));
      sw.type = "button";
      sw.addEventListener("click", function () { switchNetwork(n.node_network, sw); });
      actions.appendChild(sw);
      body.appendChild(actions);
    } else if (localStarting()) {
      body.appendChild(el("h3", null, "The built-in node is starting"));
      body.appendChild(el("p", null, "It usually answers within a few seconds."));
    } else if (isLocalMode()) {
      body.appendChild(el("h3", null, "The built-in node is not running"));
      body.appendChild(el("p", null, state.local && state.local.exited
        ? "It stopped: " + state.local.exited
        : "Nothing answered at " + w.rpc + "."));
      var act = el("div", "actions");
      var start = el("button", "primary", "Start the node");
      start.type = "button";
      start.addEventListener("click", function () { startLocal(start); });
      act.appendChild(start);
      body.appendChild(act);
    } else {
      body.appendChild(el("h3", null, "No node is answering"));
      body.appendChild(el("p", null,
        "Nothing answered at " + w.rpc + ". This wallet does not sync on its own — it asks a " +
        "Zycord node for balances and hands it what you sign — so nothing can be read or sent " +
        "until one answers."));
      body.appendChild(el("p", "small",
        "If you run a node on this computer, start it. Otherwise point this wallet at a node " +
        "you trust under Settings."));
      if (n.error) body.appendChild(el("p", "small mono muted", n.error));
    }
    card.appendChild(body);
    return card;
  }

  /* Adopt the network a node reports. Configure locks, which is right: the
   * addresses are the same on every network and the balances are not. */
  async function switchNetwork(name, button) {
    busy(button, true);
    try {
      var cfg = state.settings || await Transport.settings();
      state.wallet = await Transport.configure({
        key_path: cfg.key_path, network: name,
        mine: cfg.mine, mine_threads: cfg.mine_threads,
      });
      state.balances = null;
      state.settings = null;
      state.syncSkipped = false;
      renderChrome();
      toast("Switched to " + networkLabel(name) + ".");
      await refreshNode();
      await gateAfterKey();
    } catch (e) {
      toast(e.message, "bad");
    } finally {
      busy(button, false);
    }
  }

  /* ---------- networks and the two node forms ---------- */

  async function loadNetworks() {
    if (state.networks) return;
    try {
      state.networks = await Transport.networks();
    } catch (e) {
      state.networks = [];
    }
  }

  /* The first-run screen offers the public networks; Settings offers every
   * one this build knows, the devnet included. A saved network the screen
   * does not show falls back to the first it does. */
  function renderNetworkCards(prefix, selected) {
    var box = $(prefix + "-networks");
    box.replaceChildren();
    var list = (state.networks || []).filter(function (n) {
      return prefix !== "setup" || n.public;
    });
    if (!list.some(function (n) { return n.name === selected; }) && list.length) {
      selected = list[0].name;
    }
    list.forEach(function (n) {
      var card = el("label", "net-card" + (n.name === selected ? " selected" : ""));
      var input = document.createElement("input");
      input.type = "radio";
      input.name = prefix + "-net";
      input.value = n.name;
      input.checked = n.name === selected;
      input.addEventListener("change", function () { selectNetwork(prefix, n.name); });
      card.appendChild(input);
      card.appendChild(el("span", "net-name", n.label));
      card.appendChild(el("span", "net-sub", n.summary));
      box.appendChild(card);
    });
    $(prefix + "-network").value = selected;
  }

  function selectNetwork(prefix, name) {
    $(prefix + "-network").value = name;
    var box = $(prefix + "-networks");
    box.querySelectorAll(".net-card").forEach(function (card) {
      var input = card.querySelector("input");
      input.checked = input.value === name;
      card.classList.toggle("selected", input.value === name);
    });
  }

  async function fillForm(prefix) {
    var cfg;
    try {
      cfg = await Transport.settings();
    } catch (e) {
      return;
    }
    state.settings = cfg;
    await loadNetworks();
    $(prefix + "-key").value = cfg.key_path || "";
    renderNetworkCards(prefix, cfg.network || "zycord");
    if (prefix === "setup") {
      /* A package that lost its node program cannot work at all, and saying
       * so is better than offering a node address box: this version of the
       * wallet is its own node, and the alternative to that is not "somebody
       * else's node", it is a broken install. */
      show($("setup-nonode"), !(state.wallet && state.wallet.local_node_available));
    }
    if (prefix === "settings") {
      $("settings-mine").checked = !!cfg.mine;
      $("settings-threads").value = cfg.mine_threads || 0;
    }
  }

  /* What a person actually decides: which key file, which network, and
   * whether this computer mines. The node address is the wallet's own and is
   * never in a form. */
  function formRequest(prefix) {
    var req = {
      key_path: $(prefix + "-key").value.trim(),
      network: $(prefix + "-network").value,
      mine: false,
      mine_threads: 0,
    };
    if (prefix === "settings") {
      req.mine = $("settings-mine").checked;
      req.mine_threads = Number($("settings-threads").value) || 0;
    }
    return req;
  }

  async function configure(prefix, button) {
    busy(button, true);
    try {
      state.wallet = await Transport.configure(formRequest(prefix));
      state.balances = null;
      state.settings = null;
      renderChrome();
      return true;
    } finally {
      busy(button, false);
    }
  }

  async function browseFor(field, save) {
    try {
      var path = save ? await Transport.chooseNewKeyFile() : await Transport.chooseKeyFile();
      if (path) $(field).value = path;
    } catch (e) {
      /* The dialog was cancelled; the wallet's own error lands on the form
       * when the person continues. */
    }
  }

  /* ---------- first run ---------- */

  async function beginWizard(kind) {
    state.wizard = kind;
    await fillForm("setup");
    showGate("setup");
  }

  async function setupNext(event) {
    event.preventDefault();
    var button = $("setup-next");
    try {
      await configure("setup", button);
    } catch (e) {
      gateError(e.message);
      return;
    }
    state.syncSkipped = false;
    refreshNode();
    refreshSync();
    if (state.wizard === "create") {
      if (!$("create-key").value) $("create-key").value = await Transport.suggestKeyPath();
      show($("create-browse"), Transport.canChooseNewKeyFile());
      showGate("create");
    } else if (state.wizard === "open") {
      $("open-key").value = (state.wallet && state.wallet.key_path) || "";
      show($("open-browse"), Transport.canBrowse());
      showGate("open");
    } else {
      showGate(state.wallet.needs_key ? "welcome" : "unlock");
    }
  }

  function passphraseStrength(p) {
    var score = 0;
    if (p.length >= 8) score++;
    if (p.length >= 12) score++;
    if (p.length >= 16) score++;
    if (/[A-Z]/.test(p) && /[a-z]/.test(p)) score++;
    if (/\d/.test(p)) score++;
    if (/[^A-Za-z0-9]/.test(p)) score++;
    if (/\s/.test(p) && p.length >= 20) score++;
    return Math.min(score, 6);
  }

  function renderStrength() {
    var p = $("create-pass").value;
    var bar = $("create-strength");
    var s = passphraseStrength(p);
    var pct = p ? Math.max(12, Math.round((s / 6) * 100)) : 0;
    var colour = s <= 2 ? "var(--error)" : s <= 4 ? "var(--warn-line)" : "var(--ok)";
    bar.style.setProperty("--w", pct + "%");
    bar.style.setProperty("--c", colour);
    var note = bar.nextElementSibling;
    if (!note || !note.classList.contains("strength-note")) {
      note = el("div", "strength-note");
      bar.insertAdjacentElement("afterend", note);
    }
    text(note, !p ? "" : s <= 2 ? "Weak — a longer passphrase is the single biggest improvement."
      : s <= 4 ? "Fair. Four or five unrelated words is both stronger and easier to remember."
      : "Strong.");
  }

  async function createWallet(event) {
    event.preventDefault();
    gateError("");
    var path = $("create-key").value.trim();
    var pass = $("create-pass").value;
    var again = $("create-pass2").value;
    if (!path) { gateError("Choose where to save the key file."); return; }
    if (!pass) { gateError("A passphrase is required. There is no unencrypted key format."); return; }
    if (pass !== again) { gateError("The two passphrases do not match."); return; }
    var button = $("create-submit");
    busy(button, true);
    try {
      state.wallet = await Transport.create({ key_path: path, passphrase: pass });
      $("create-pass").value = "";
      $("create-pass2").value = "";
      renderStrength();
      renderChrome();
      renderDone();
      showGate("done");
    } catch (e) {
      gateError(e.message);
    } finally {
      busy(button, false);
    }
  }

  function renderDone() {
    var w = state.wallet;
    var box = $("done-addresses");
    box.replaceChildren();
    [["Persistent address — share this one", w.persistent], ["One-shot address — for a single payment", w.one_shot]].forEach(function (pair) {
      var row = el("div", "done-addr");
      row.appendChild(el("div", "kind", pair[0]));
      var line = el("div", "addr-row");
      line.appendChild(el("div", "addr", pair[1]));
      line.appendChild(copyButton(pair[1]));
      row.appendChild(line);
      box.appendChild(row);
    });
    text($("done-keypath"), w.key_path);
  }

  async function openWallet(event) {
    event.preventDefault();
    gateError("");
    var path = $("open-key").value.trim();
    if (!path) { gateError("Choose the key file to open."); return; }
    var button = $("open-submit");
    busy(button, true);
    try {
      var cfg = state.settings || await Transport.settings();
      state.wallet = await Transport.configure({
        key_path: path, network: cfg.network,
        mine: cfg.mine, mine_threads: cfg.mine_threads,
      });
      state.settings = null;
      renderChrome();
      await gateAfterKey();
    } catch (e) {
      gateError(e.message);
    } finally {
      busy(button, false);
    }
  }

  /* ---------- the node this wallet runs, and how far along it is ---------- */

  async function refreshSync() {
    try {
      state.sync = await Transport.sync();
    } catch (e) {
      if (await handleAuthFailure(e)) return;
      state.sync = null;
    }
    if (isLocalMode()) {
      try { state.local = await Transport.localNode(); } catch (e) { /* shown as no node */ }
    }
    renderStatusPill();
    if (!$("gate-sync").classList.contains("hidden")) renderSync();
    if (!$("panel-node").classList.contains("hidden")) renderLocalNode();
  }

  /* Start the bundled node if this wallet is set to use one and it is not
   * running. Called on launch and after a Start button. */
  async function ensureLocalNode() {
    if (!isLocalMode() || !state.wallet.local_node_available) return;
    try {
      state.local = await Transport.localNode();
      if (state.local.running || state.local.adopted) return;
      state.local = await Transport.startLocalNode();
    } catch (e) {
      state.localError = e.message;
    }
  }

  async function startLocal(button) {
    busy(button, true);
    state.localError = null;
    try {
      state.local = await Transport.startLocalNode();
      toast("Node started");
    } catch (e) {
      state.localError = e.message;
      toast(e.message, "bad");
    } finally {
      busy(button, false);
      await refreshNode();
      await refreshSync();
    }
  }

  async function stopLocal(button) {
    busy(button, true);
    try {
      state.local = await Transport.stopLocalNode();
      toast("Node stopped");
    } catch (e) {
      toast(e.message, "bad");
    } finally {
      busy(button, false);
      await refreshNode();
      await refreshSync();
    }
  }

  /* Whether the gate should hold on the sync screen: the node is known to
   * be behind, or is the built-in one and has not answered yet. */
  function shouldWaitForSync() {
    if (state.syncSkipped) return false;
    var sy = state.sync;
    if (sy && sy.reachable) return !!sy.syncing;
    return isLocalMode();
  }

  /* Where the gate goes once a key file is configured. */
  async function gateAfterKey() {
    if (shouldWaitForSync()) {
      showGate("sync");
      renderSync();
      return;
    }
    showGate("unlock");
  }

  function renderSync() {
    var sy = state.sync;
    var n = state.node;
    var bar = $("sync-bar");
    var err = $("sync-error");
    show(err, false);
    show($("sync-retry"), false);
    show($("sync-switch"), !!(state.wallet && state.wallet.configurable));
    var reachable = sy && sy.reachable;

    if (!reachable) {
      var local = state.local;
      if (state.localError || (local && local.exited)) {
        text($("sync-title"), "The node stopped");
        text($("sync-message"), "The built-in node is not running.");
        text(err, state.localError || local.exited);
        show(err, true);
        show($("sync-retry"), true);
        bar.className = "progress-bar";
        bar.style.setProperty("--w", "0%");
      } else if (isLocalMode()) {
        text($("sync-title"), "Starting the node");
        text($("sync-message"), "The built-in node is starting. It usually answers within a few seconds.");
        bar.className = "progress-bar indeterminate";
      } else {
        text($("sync-title"), "No node");
        text($("sync-message"), (n && n.mismatch)
          ? "The node at " + state.wallet.rpc + " is on " + networkLabel(n.node_network) + ", not " + networkLabel(state.wallet.network) + "."
          : "Nothing answered at " + (state.wallet ? state.wallet.rpc : "the node") + ".");
        bar.className = "progress-bar";
        bar.style.setProperty("--w", "0%");
      }
      text($("sync-detail"), "");
    } else if (sy.syncing) {
      var peersOnly = sy.no_peers && !sy.stale && !sy.behind_floor;
      text($("sync-title"), peersOnly ? "Looking for peers" : "Syncing the chain");
      text($("sync-message"), peersOnly
        ? "The node has nobody to hear about new blocks from yet. It keeps trying."
        : sy.message + ". The first sync downloads the whole chain; after that the node keeps up on its own.");
      bar.className = "progress-bar" + (peersOnly || sy.progress <= 0 ? " indeterminate" : "");
      if (!peersOnly && sy.progress > 0) bar.style.setProperty("--w", sy.progress.toFixed(1) + "%");
      text($("sync-detail"), "height " + sy.height + " · " + sy.peers + " peers · tip " + humanAge(sy.tip_age_seconds) + " old" +
        (sy.progress > 0 && !peersOnly ? " · " + sy.progress.toFixed(1) + "%" : ""));
    } else {
      text($("sync-title"), "In sync");
      text($("sync-message"), "The node is up to date.");
      bar.className = "progress-bar";
      bar.style.setProperty("--w", "100%");
      text($("sync-detail"), "height " + sy.height + " · " + sy.peers + " peers");
      // Done: move on without being asked.
      if (!$("gate-sync").classList.contains("hidden")) showGate("unlock");
      return;
    }

    var log = state.local && state.local.log ? state.local.log.slice(-40).join("\n") : "";
    show($("sync-log-box"), isLocalMode() && !!log);
    text($("sync-log"), log);
  }

  function humanAge(secs) {
    secs = Number(secs) || 0;
    if (secs < 120) return secs + " s";
    if (secs < 7200) return Math.floor(secs / 60) + " min";
    if (secs < 172800) return Math.floor(secs / 3600) + " h";
    return Math.floor(secs / 86400) + " days";
  }

  function renderLocalNode() {
    var box = $("localnode");
    box.replaceChildren();
    if (!isLocalMode()) return;
    var l = state.local;
    var card = el("div", "card");
    card.appendChild(el("div", "kind", "Built-in node"));
    if (!l || !l.available) {
      card.appendChild(el("p", "muted", "No node is bundled with this build."));
      box.appendChild(card);
      return;
    }
    var status = l.adopted ? "using a node already running on this computer"
      : l.running ? "running" + (l.options && l.options.mine ? ", mining" : "") : "stopped";
    card.appendChild(kv([
      ["status", status],
      ["address", l.rpc],
      ["process", l.running ? "pid " + l.pid + ", up " + humanAge(l.uptime_seconds) : ""],
      ["mining to", l.options && l.options.mine ? l.options.payout : ""],
      ["data", l.data_dir],
      ["binary", l.binary],
      ["stopped because", l.exited],
    ]));
    var actions = el("div", "mini-actions");
    if (l.running) {
      var stop = el("button", "ghost", "Stop the node");
      stop.type = "button";
      stop.addEventListener("click", function () { stopLocal(stop); });
      actions.appendChild(stop);
    } else if (!l.adopted) {
      var start = el("button", "primary small", "Start the node");
      start.type = "button";
      start.addEventListener("click", function () { startLocal(start); });
      actions.appendChild(start);
    }
    card.appendChild(actions);
    if (l.log && l.log.length) {
      var det = el("details");
      det.appendChild(el("summary", null, "Node log"));
      det.appendChild(el("pre", "log", l.log.slice(-60).join("\n")));
      card.appendChild(det);
    }
    box.appendChild(card);
  }

  /* ---------- panels ---------- */

  function renderOverview() {
    var hero = $("total-amount");
    var sub = $("total-sub");
    var box = $("balances");
    box.replaceChildren();
    var note = $("overview-node");
    note.replaceChildren();
    var callout = nodeCallout();
    if (callout) note.appendChild(callout);

    var b = state.balances;
    if (!b) {
      hero.replaceChildren(document.createTextNode(callout ? "—" : "…"));
      text(sub, callout ? "Balances cannot be read until a node answers." : "Reading balances…");
      return;
    }
    var total = 0n;
    b.addresses.forEach(function (a) { total += BigInt(a.balance); });
    hero.replaceChildren(document.createTextNode(formatZcd(total.toString())), el("span", "unit", "ZCD"));
    text(sub, formatDrops(total.toString()) + " drops" +
      (b.confirmed ? " · cross-checked against a second node"
        : isLocalMode() ? " · computed by this computer's own node"
        : " · as reported by " + (state.wallet ? state.wallet.rpc : "the node")));

    b.addresses.forEach(function (a) {
      var card = el("div", "card");
      var head = el("div", "card-head");
      head.appendChild(el("span", "kind", kindLabel(a.kind)));
      var amt = el("span", "amount", formatZcd(a.balance));
      amt.appendChild(el("span", "unit", "ZCD"));
      head.appendChild(amt);
      card.appendChild(head);
      var row = el("div", "addr-row");
      row.appendChild(el("div", "addr", a.address));
      row.appendChild(copyButton(a.address));
      card.appendChild(row);
      if (a.spent) {
        card.appendChild(el("div", "spent", "Spent — this address can neither send nor receive any more."));
      }
      box.appendChild(card);
    });
    if (!b.confirmed) {
      box.appendChild(el("p", "muted small",
        "One node was asked. Add a second, independent node under Settings to have every " +
        "balance cross-checked before an irreversible spend."));
    }
  }

  function renderNode() {
    var n = state.node;
    var box = $("node");
    box.replaceChildren();
    renderStatusPill();
    renderLocalNode();
    if (!n) return;
    var callout = nodeCallout();
    if (callout) {
      box.appendChild(callout);
      return;
    }

    var chain = el("div", "card");
    chain.appendChild(el("div", "kind", "Chain"));
    chain.appendChild(kv([
      ["network", networkLabel(n.network) + " (chain id " + n.chain_id + ")"],
      ["height", n.height],
      ["tip", n.tip],
      ["state root", n.state_root],
      ["address", state.wallet ? state.wallet.rpc : ""],
    ]));
    box.appendChild(chain);

    var fees = el("div", "card");
    fees.appendChild(el("div", "kind", "Fees and ceilings in force"));
    fees.appendChild(kv([
      ["sequential base fee", n.seq_base_fee + " drops/gas"],
      ["parallel base fee", n.par_base_fee + " drops/gas"],
      ["skip fee", n.skip_fee + " drops"],
      ["sequential target", n.seq_gas_target],
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
    net.appendChild(el("div", "kind", "Peers"));
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
    [
      ["Persistent address", w.persistent,
        "For anything paid more than once — a mining payout, a donation, a shop. It can never be burned, so it is always safe to hand out."],
      ["One-shot address", w.one_shot,
        "For a single expected payment. It is burned the first time you spend from it, which is what keeps that payment unlinkable to the next."],
    ].forEach(function (item) {
      var card = el("div", "card receive-card");
      card.appendChild(el("div", "kind", item[0]));
      card.appendChild(el("div", "addr", item[1]));
      var row = el("div", "addr-row");
      row.appendChild(el("p", "muted small", item[2]));
      row.appendChild(copyButton(item[1], "Copy address"));
      card.appendChild(row);
      /* A burned address still derives from the key and still looks like an
       * address, so a receive screen that showed it without saying so would
       * be inviting a payment into a cell nobody can open. */
      if (isSpent(item[1])) {
        card.appendChild(el("div", "spent",
          "Spent — anything paid here now is lost. Do not give this address out again."));
      }
      box.appendChild(card);
    });
  }

  /* ---------- send ----------
   *
   * The review is the trusted display. The payee and the refund address come
   * from the form and from the key file, so nothing a node says can change
   * them; the balance is the node's word and is labelled with whose word it
   * is. */

  function sendError(message) {
    var box = $("send-error");
    text(box, message || "");
    show(box, !!message);
  }

  function sendSource() {
    var checked = document.querySelector("input[name=send-source]:checked");
    return checked ? checked.value : "persistent";
  }

  function buildRequest() {
    var sweep = $("send-sweep").checked;
    var to = $("send-to").value.trim();
    if (!to) throw new Error("Enter the address to pay.");
    if (!isAddress(to)) throw new Error("That is not a Zycord address: expected 0x01… or 0x02… followed by 62 hex characters.");
    if (!sweep && !$("send-amount").value.trim()) throw new Error("Enter an amount, or tick \"Send the whole balance\".");
    return {
      to: to,
      one_shot: sendSource() === "one-shot",
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
    var button = $("send-preview");
    busy(button, true);
    try {
      var preview = await Transport.send(req);
      state.pending = { request: req, preview: preview };
      renderReview(preview, req);
      $("send-review").scrollIntoView({ behavior: "smooth", block: "nearest" });
    } catch (e) {
      if (await handleAuthFailure(e)) return;
      sendError(e.message);
    } finally {
      busy(button, false);
    }
  }

  function renderReview(preview, request) {
    var box = $("send-review");
    box.replaceChildren();
    box.classList.toggle("irreversible", !!preview.one_shot_drain);
    show(box, true);

    box.appendChild(el("h3", null, preview.one_shot_drain
      ? "Review — this cannot be undone"
      : "Review before sending"));
    var amount = el("div", "review-amount", formatZcd(preview.amount));
    amount.appendChild(el("span", "unit", "ZCD"));
    box.appendChild(amount);

    box.appendChild(kv([
      ["to", preview.to],
      ["from", preview.from + " (" + (request.one_shot ? "one-shot" : "persistent") + ")"],
      ["exact amount", formatDrops(preview.amount) + " drops"],
      ["fee now", formatDrops(preview.fee_now) + " drops, of which " + formatDrops(preview.tip) + " is the producer's tip"],
      ["reserved", formatDrops(preview.reserved) + " drops, refunded within the same block"],
      ["refund to", preview.refund],
      [preview.primary_rpc + " reports the source holds", formatDrops(preview.held) + " drops"],
      ["valid until height", preview.ttl + " (now " + preview.height + ")"],
    ]));

    if (preview.one_shot_drain) {
      var notice = el("div", "notice");
      notice.appendChild(el("strong", null, "Spending from a one-shot address burns it. "));
      notice.appendChild(document.createTextNode(
        "The amount above is everything " + preview.primary_rpc + " says the address holds. " +
        "If that node under-reported the balance, whatever it left out is destroyed the instant " +
        "this applies, with no error at any layer."));
      notice.appendChild(el("p", "small", preview.confirm_rpc
        ? preview.confirm_rpc + " was asked the same questions and gave the same answers."
        : "Not independently confirmed — only " + preview.primary_rpc + " was asked. A second node " +
          "under Settings would cross-check this number first."));
      box.appendChild(notice);
    }

    var actions = el("div", "review-actions");
    var cancel = el("button", "ghost", "Cancel");
    cancel.type = "button";
    cancel.addEventListener("click", function () {
      show(box, false);
      state.pending = null;
    });
    var confirm = el("button", preview.one_shot_drain ? "danger" : "primary",
      preview.one_shot_drain ? "Burn the address and send" : "Send " + formatZcd(preview.amount) + " ZCD");
    confirm.type = "button";
    confirm.addEventListener("click", function () {
      busy(confirm, true);
      cancel.disabled = true;
      submit(request, preview).catch(function () {
        busy(confirm, false);
        cancel.disabled = false;
      });
    });
    actions.appendChild(cancel);
    actions.appendChild(confirm);
    box.appendChild(actions);
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
      ok.replaceChildren();
      ok.appendChild(el("h3", null, "Sent"));
      ok.appendChild(el("p", null,
        formatZcd(result.amount) + " ZCD is on its way to " + shorten(result.to) +
        ". It commits by height " + result.ttl + " or expires; there is nothing else to do."));
      var row = el("div", "addr-row");
      row.appendChild(el("div", "addr", "certificate " + result.certificate));
      row.appendChild(copyButton(result.certificate, "Copy id"));
      ok.appendChild(row);
      show(ok, true);
      $("send-form").reset();
      $("send-amount").disabled = false;
      renderSourceNote();
      toast("Sent");
      await refreshBalances();
    } catch (e) {
      if (await handleAuthFailure(e)) return;
      sendError(e.message);
      throw e;
    }
  }

  function renderSourceNote() {
    var oneShot = sendSource() === "one-shot";
    text($("send-source-note"), oneShot
      ? "Spending from the one-shot address burns it, so it always sends its whole balance."
      : "Your everyday address. It can be spent from as often as you like.");
    var sweep = $("send-sweep");
    if (oneShot) {
      sweep.checked = true;
      sweep.disabled = true;
    } else {
      sweep.disabled = false;
    }
    $("send-amount").disabled = sweep.checked;
    if (sweep.checked) $("send-amount").value = "";
  }

  /* ---------- state changes that can arrive mid-call ---------- */

  /* Two failures are states rather than errors, and both can arrive in the
   * middle of any call: the idle lock fired, or the token this page holds is
   * no longer the running wallet's (it restarted, so a new one was printed).
   * Every caller routes through here so that neither ends as an unhandled
   * rejection with a window that looks fine and does nothing. */
  async function handleAuthFailure(err) {
    if (!err) return false;
    if (err.unauthorised) {
      Transport.clearToken();
      showGate("token");
      gateError("This token was refused. The wallet was probably restarted — reopen the URL it printed.");
      return true;
    }
    if (!err.locked) return false;
    state.balances = null;
    try {
      await loadWallet();
    } catch (e) {
      showGate("unlock");
      gateError(e.message);
    }
    return true;
  }

  async function loadWallet() {
    state.wallet = await Transport.wallet();
    await loadNetworks();
    renderChrome();
    if (state.wallet.needs_key) {
      /* First run of the desktop application: there is no key file to
       * unlock yet, which is a different screen from a locked one. */
      if (state.wallet.configurable) {
        showGate("welcome");
      } else {
        showGate("unlock");
        gateError("No key file was given. Start again with --key.");
      }
      return false;
    }
    if (state.wallet.locked) {
      await gateAfterKey();
      return false;
    }
    showApp();
    renderReceive();
    // Deliberately not awaited: the check talks to a release host, and a slow
    // or unreachable one must not delay a window somebody is looking at.
    refreshUpdate();
    return true;
  }

  async function refreshBalances() {
    try {
      state.balances = await Transport.balances();
      renderOverview();
      renderReceive();
    } catch (e) {
      if (await handleAuthFailure(e)) return;
      state.balances = null;
      renderOverview();
      if (!nodeCallout()) {
        $("balances").replaceChildren(el("p", "error", e.message));
      }
    }
  }

  async function refreshNode() {
    try {
      state.node = await Transport.node();
    } catch (e) {
      if (await handleAuthFailure(e)) return;
      state.node = { reachable: false, error: e.message };
    }
    renderStatusPill();
    if (!$("panel-node").classList.contains("hidden")) renderNode();
    if (!$("panel-overview").classList.contains("hidden")) renderOverview();
  }

  async function unlock(event) {
    event.preventDefault();
    gateError("");
    var field = $("passphrase");
    var button = $("unlock");
    busy(button, true);
    try {
      state.wallet = await Transport.unlock(field.value);
      field.value = "";
      renderChrome();
      showApp();
      openPanel("panel-overview");
      renderReceive();
      await Promise.all([refreshBalances(), refreshNode()]);
    } catch (e) {
      gateError(e.message);
      field.select();
    } finally {
      busy(button, false);
    }
  }

  async function lock() {
    try {
      state.wallet = await Transport.lock();
      state.balances = null;
      renderChrome();
      showGate("unlock");
    } catch (e) {
      if (await handleAuthFailure(e)) return;
      showGate("unlock");
      gateError(e.message);
    }
  }

  /* ---------- updates (desktop only) ----------
   *
   * Quiet by construction: nothing is contacted until the person has said it
   * may be, and "not yet asked" is not consent. */

  async function refreshUpdate() {
    if (!Transport.canUpdate()) return;
    var bar = $("update-bar");
    var report;
    try {
      report = await Transport.updateStatus();
    } catch (err) {
      return; /* never a dialog: a wallet that cannot reach a release host is still a wallet */
    }
    if (!report) return;

    if (!report.asked) {
      text($("update-text"), "Check for new versions of the wallet? Releases are signed. " +
        "Nothing is downloaded until you say so.");
      show($("update-yes"), true);
      $("update-yes").textContent = "Yes, check";
      show($("update-open"), false);
      show($("update-no"), true);
      $("update-no").textContent = "No";
      bar.classList.remove("security");
      show(bar, true);
      return;
    }
    if (!report.available) { show(bar, false); return; }

    var line = (report.security ? "Security release " : "Version ") + report.available +
      " is available (you have " + report.current + ").";
    if (report.note) line += " " + report.note;
    if (!report.installable && report.reason) line += " " + report.reason;
    text($("update-text"), line);
    bar.classList.toggle("security", !!report.security);
    show($("update-yes"), report.installable);
    $("update-yes").textContent = "Install";
    show($("update-open"), !report.installable);
    show($("update-no"), true);
    $("update-no").textContent = "Not now";
    show(bar, true);
  }

  async function onUpdateYes() {
    var report = await Transport.updateStatus();
    if (report && !report.asked) {
      await Transport.setUpdateCheck(true);
      await refreshUpdate();
      return;
    }
    text($("update-text"), "Installing…");
    show($("update-yes"), false);
    show($("update-no"), false);
    try {
      var done = await Transport.installUpdate();
      text($("update-text"), (done && done.reason) || "Installed. Reopen the wallet to use it.");
    } catch (err) {
      text($("update-text"), "Update failed: " + (err && err.message ? err.message : err) +
        " Nothing was changed.");
      show($("update-open"), true);
    }
  }

  async function onUpdateNo() {
    var report = await Transport.updateStatus();
    if (report && !report.asked) await Transport.setUpdateCheck(false);
    show($("update-bar"), false);
  }

  /* ---------- wiring ---------- */

  function openPanel(id) {
    document.querySelectorAll(".tab").forEach(function (t) {
      t.classList.toggle("active", t.dataset.panel === id);
    });
    document.querySelectorAll(".panel").forEach(function (p) { p.classList.add("hidden"); });
    show($(id), true);
    if (id === "panel-node") renderNode();
    if (id === "panel-overview") { renderOverview(); if (!state.balances) refreshBalances(); }
    if (id === "panel-receive") renderReceive();
    if (id === "panel-settings") fillForm("settings").then(function () {
      show($("settings-browse"), Transport.canBrowse());
    });
  }

  function wire() {
    document.querySelectorAll(".tab").forEach(function (tab) {
      tab.addEventListener("click", function () { openPanel(tab.dataset.panel); });
    });
    $("go-send").addEventListener("click", function () { openPanel("panel-send"); });
    $("go-receive").addEventListener("click", function () { openPanel("panel-receive"); });
    $("node-pill").addEventListener("click", function () { openPanel("panel-node"); });

    $("send-form").addEventListener("submit", review);
    $("refresh-balance").addEventListener("click", function () {
      refreshBalances();
      refreshNode();
    });
    $("refresh-node").addEventListener("click", refreshNode);
    $("lock").addEventListener("click", lock);

    $("gate-unlock").addEventListener("submit", unlock);
    $("gate-token").addEventListener("submit", function (e) {
      e.preventDefault();
      start();
    });
    $("unlock-switch").addEventListener("click", function () { showGate("welcome"); });
    $("settings-switch").addEventListener("click", async function () {
      try { state.wallet = await Transport.lock(); } catch (e) { /* already locked */ }
      state.balances = null;
      showGate("welcome");
    });

    $("welcome-create").addEventListener("click", function () { beginWizard("create"); });
    $("welcome-open").addEventListener("click", function () { beginWizard("open"); });
    $("gate-setup").addEventListener("submit", setupNext);
    $("setup-back").addEventListener("click", function () { showGate("welcome"); });
    $("gate-create").addEventListener("submit", createWallet);
    $("create-back").addEventListener("click", function () { showGate("setup"); });
    $("create-browse").addEventListener("click", function () { browseFor("create-key", true); });
    $("create-pass").addEventListener("input", renderStrength);
    $("gate-open").addEventListener("submit", openWallet);
    $("open-back").addEventListener("click", function () { showGate("setup"); });
    $("open-browse").addEventListener("click", function () { browseFor("open-key", false); });
    $("done-continue").addEventListener("click", function () {
      showApp();
      openPanel("panel-overview");
      renderReceive();
      refreshBalances();
      refreshNode();
      refreshSync();
    });

    $("settings-form").addEventListener("submit", async function (e) {
      e.preventDefault();
      var box = $("settings-error");
      show(box, false);
      try {
        await configure("settings", e.submitter);
        toast("Saved. The wallet is locked.");
        state.syncSkipped = false;
        await refreshNode();
        await refreshSync();
        await gateAfterKey();
      } catch (err) {
        text(box, err.message);
        show(box, true);
      }
    });
    $("settings-browse").addEventListener("click", function () { browseFor("settings-key", false); });

    $("sync-continue").addEventListener("click", function () {
      state.syncSkipped = true;
      showGate("unlock");
    });
    $("sync-retry").addEventListener("click", function () { startLocal($("sync-retry")); });
    $("sync-switch").addEventListener("click", function () { showGate("welcome"); });

    $("update-yes").addEventListener("click", onUpdateYes);
    $("update-no").addEventListener("click", onUpdateNo);
    $("update-open").addEventListener("click", function () { Transport.openReleasePage(); });

    $("send-sweep").addEventListener("change", renderSourceNote);
    document.querySelectorAll("input[name=send-source]").forEach(function (r) {
      r.addEventListener("change", renderSourceNote);
    });
  }

  async function start() {
    if (Transport.mode === "browser") {
      var typed = $("token").value.trim();
      if (typed) Transport.setToken(typed);
      /* A handoff that would not exchange is reported whatever else this tab
       * has, and before anything else can overwrite the message. The benign
       * reading is that the browser was slow or the tab was reopened. The one
       * that matters is that something else on this machine spent the handoff
       * first — and that case is not conditional on this tab having no token. */
      if (Transport.handoffError) {
        showGate("token");
        gateError(Transport.handoffError);
        Transport.clearToken();
        return;
      }
      if (!Transport.hasToken()) {
        showGate("token");
        return;
      }
    }
    try {
      state.wallet = await Transport.wallet();
      await ensureLocalNode();
      await refreshNode();
      await refreshSync();
      var unlocked = await loadWallet();
      if (unlocked) {
        openPanel("panel-overview");
        await refreshBalances();
      }
    } catch (e) {
      if (await handleAuthFailure(e)) return;
      showGate(Transport.hasToken() ? "unlock" : "token");
      gateError(e.message);
    }
  }

  async function boot() {
    wire();
    await Transport.init();
    await start();
    /* A slow poll for the node status, and a faster one while the sync
     * screen is up. Balances are refreshed on demand and after a send, not
     * on a timer: a wallet that polls a balance every few seconds is a wallet
     * that has told the node operator which addresses it cares about, over
     * and over. */
    setInterval(function () {
      refreshNode();
      refreshSync();
    }, 15000);
    setInterval(function () {
      if (!$("gate-sync").classList.contains("hidden")) {
        refreshNode();
        refreshSync();
      }
    }, 2000);
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
