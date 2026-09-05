/* transport.js — the only file that knows how this page reaches the wallet.
 *
 * There are two ways, and the rest of the interface is written against
 * neither of them:
 *
 *   browser  — `zcd ui` serves these files over a loopback HTTP server, and
 *              the calls below are fetch() with a bearer token.
 *   desktop  — the Wails shell embeds the same files in a native webview and
 *              binds the Go API directly, so the calls are native and the
 *              application opens no TCP port at all.
 *
 * The method names are the Go method names in both cases. That is the whole
 * trick: one API type, two ways to reach it, so the two front ends cannot
 * drift apart into two behaviours.
 */

(function () {
  "use strict";

  var TOKEN_KEY = "t";
  var HANDOFF_KEY = "h";
  var token = null;
  var bridge = null;
  var mode = "browser";

  function sleep(ms) {
    return new Promise(function (r) { setTimeout(r, ms); });
  }

  /* The desktop shell exposes bound Go structs under window.go.<pkg>.<Type>.
   * Rather than hard-coding that path — which would break silently if the
   * package or type were renamed — look for the object that has the methods
   * this interface actually calls. */
  function findBridge() {
    var go = window.go;
    if (!go) return null;
    for (var pkg in go) {
      if (!Object.prototype.hasOwnProperty.call(go, pkg)) continue;
      for (var name in go[pkg]) {
        if (!Object.prototype.hasOwnProperty.call(go[pkg], name)) continue;
        var obj = go[pkg][name];
        if (obj && typeof obj.Wallet === "function" && typeof obj.Send === "function") {
          return obj;
        }
      }
    }
    return null;
  }

  /* Wails injects its bindings shortly after the document loads, so a page
   * that asked once and gave up would fall back to HTTP inside the desktop
   * application — where there is no HTTP server to fall back to. Only wait at
   * all when there is a sign of a shell: in a plain browser window neither
   * window.wails nor window.go ever appears, and the first check settles it. */
  async function resolveBridge() {
    if (!window.wails && !window.go) return null;
    for (var i = 0; i < 150; i++) {
      var found = findBridge();
      if (found) return found;
      await sleep(20);
    }
    return null;
  }

  /* sessionStorage, not localStorage. The token dies with the tab, which is
   * the same lifetime it already had in this page's memory — the only thing
   * this buys is that a reload does not send the user back to the terminal
   * for the URL. localStorage would outlive the wallet process that issued
   * it, and would still be there for the next unrelated thing to bind this
   * port. */
  function rememberToken(t) {
    try { window.sessionStorage.setItem("zcd.token", t); } catch (e) { /* private mode */ }
  }

  function forgetToken() {
    try { window.sessionStorage.removeItem("zcd.token"); } catch (e) { /* private mode */ }
  }

  function recallToken() {
    try { return window.sessionStorage.getItem("zcd.token"); } catch (e) { return null; }
  }

  /* The fragment carries one of two things, and never both.
   *
   *   t= the session token, from the URL `zcd ui` printed in the terminal.
   *   h= a single-use handoff, from the browser `zcd ui` launched itself.
   *
   * The split exists because launching a browser puts the URL on another
   * process's command line, which every local user can read — /proc on Linux,
   * the process table on macOS. A handoff scraped from there is worth one
   * exchange inside a few minutes, and spending it makes this page fail
   * visibly rather than quietly sharing the session. See
   * webui.Server.BrowserURL. */
  function readHash() {
    var hash = window.location.hash || "";
    if (hash.charAt(0) === "#") hash = hash.slice(1);
    var params = new URLSearchParams(hash);
    var out = { token: params.get(TOKEN_KEY), handoff: params.get(HANDOFF_KEY) };
    if (!out.token && !out.handoff) return out;
    /* Clear it from the address bar: both are session secrets and a URL in a
     * history entry outlives the window that needed it. */
    try {
      window.history.replaceState(null, "", window.location.pathname);
    } catch (e) { /* a file:// or restricted context; not worth failing over */ }
    return out;
  }

  /* Trade a handoff for the session token. The request carries no
   * Authorization header — having one is what this is for — and the server
   * still applies its Host and same-origin checks. */
  async function redeem(handoff) {
    var resp = await fetch("api/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ handoff: handoff }),
      credentials: "omit",
      cache: "no-store",
    });
    var payload = null;
    try { payload = JSON.parse(await resp.text()); } catch (e) { payload = null; }
    if (!resp.ok || !payload || !payload.token) {
      throw new Error((payload && payload.error) || ("could not start a session: HTTP " + resp.status));
    }
    return payload.token;
  }

  function walletError(message, status) {
    var err = new Error(message);
    err.locked = status === 423;
    err.unauthorised = status === 401;
    return err;
  }

  async function http(method, path, body) {
    var headers = {};
    if (token) headers["Authorization"] = "Bearer " + token;
    if (body !== undefined) headers["Content-Type"] = "application/json";

    var resp;
    try {
      resp = await fetch(path, {
        method: method,
        headers: headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        /* Never attach ambient credentials; the bearer token is the whole of
         * this page's authority. */
        credentials: "omit",
        cache: "no-store",
      });
    } catch (e) {
      throw new Error("cannot reach the wallet process: " + e.message);
    }

    var text = await resp.text();
    var payload = null;
    if (text) {
      try { payload = JSON.parse(text); } catch (e) { payload = null; }
    }
    if (!resp.ok) {
      var message = (payload && payload.error) || text || ("HTTP " + resp.status);
      throw walletError(message, resp.status);
    }
    return payload;
  }

  /* The desktop bridge rejects with a string or an Error depending on the
   * runtime version; normalise both, and preserve the locked signal the
   * interface uses to decide whether to show the unlock screen. */
  async function viaBridge(method, arg) {
    try {
      return arg === undefined ? await bridge[method]() : await bridge[method](arg);
    } catch (e) {
      var message = typeof e === "string" ? e : (e && e.message) || String(e);
      var err = new Error(message);
      err.locked = /wallet: locked/.test(message);
      throw err;
    }
  }

  var Transport = {
    get mode() { return mode; },

    hasToken: function () { return mode === "desktop" || !!token; },

    setToken: function (t) {
      token = (t || "").trim();
      if (token) rememberToken(token);
    },

    clearToken: function () {
      token = null;
      forgetToken();
    },

    init: async function () {
      bridge = await resolveBridge();
      if (bridge) {
        mode = "desktop";
        return mode;
      }
      mode = "browser";
      var got = readHash();
      var t = got.token;
      if (!t && got.handoff) {
        /* A failed exchange is not fatal here: fall through to whatever this
         * tab already had, so a reload after the handoff was spent still
         * works. What it must not do is silently look like "no token", which
         * is why the reason is kept for the interface to show. */
        try {
          t = await redeem(got.handoff);
        } catch (e) {
          Transport.handoffError = e.message;
        }
      }
      if (t) {
        rememberToken(t);
      } else {
        t = recallToken();
      }
      token = t;
      return mode;
    },

    wallet: function () {
      return bridge ? viaBridge("Wallet") : http("GET", "api/wallet");
    },
    node: function () {
      return bridge ? viaBridge("Node") : http("GET", "api/node");
    },
    balances: function () {
      return bridge ? viaBridge("Balances") : http("GET", "api/balances");
    },
    balance: function (addr) {
      return bridge ? viaBridge("Balance", addr) : http("GET", "api/balance?addr=" + encodeURIComponent(addr));
    },
    unlock: function (passphrase) {
      return bridge ? viaBridge("Unlock", passphrase) : http("POST", "api/unlock", { passphrase: passphrase });
    },
    lock: function () {
      return bridge ? viaBridge("Lock") : http("POST", "api/lock", {});
    },
    send: function (req) {
      return bridge ? viaBridge("Send", req) : http("POST", "api/send", req);
    },
    retire: function (req) {
      return bridge ? viaBridge("Retire", req) : http("POST", "api/retire", req);
    },
    settings: function () {
      return bridge ? viaBridge("Settings") : http("GET", "api/settings");
    },
    configure: function (req) {
      return bridge ? viaBridge("Configure", req) : http("POST", "api/configure", req);
    },
    networks: function () {
      return bridge ? viaBridge("Networks") : http("GET", "api/networks");
    },
    /* Generate a key and write it encrypted. Refused by `zcd ui`, which was
     * given its key file on the command line; the desktop application is
     * where somebody without a command line starts. */
    create: function (req) {
      return bridge ? viaBridge("Create", req) : http("POST", "api/create", req);
    },

    /* Where the node is, and the node the wallet runs beside itself when it
     * ships one. `zcd ui` answers the last three with "no such node". */
    sync: function () {
      return bridge ? viaBridge("Sync") : http("GET", "api/sync");
    },
    localNode: function () {
      return bridge ? viaBridge("LocalNode") : http("GET", "api/localnode");
    },
    startLocalNode: function () {
      return bridge ? viaBridge("StartLocalNode") : http("POST", "api/localnode/start", {});
    },
    stopLocalNode: function () {
      return bridge ? viaBridge("StopLocalNode") : http("POST", "api/localnode/stop", {});
    },

    /* Desktop only: native file dialogs, and a sensible default location for
     * a new key file. There is no browser equivalent — a page cannot learn a
     * path, only receive file contents — so the browser build asks the person
     * to type one, which is what they already did to start `zcd ui`. */
    canBrowse: function () {
      return !!(bridge && typeof bridge.ChooseKeyFile === "function");
    },
    chooseKeyFile: function () {
      return viaBridge("ChooseKeyFile");
    },
    canChooseNewKeyFile: function () {
      return !!(bridge && typeof bridge.ChooseNewKeyFile === "function");
    },
    chooseNewKeyFile: function () {
      return viaBridge("ChooseNewKeyFile");
    },
    suggestKeyPath: function () {
      if (!bridge || typeof bridge.SuggestKeyPath !== "function") return Promise.resolve("");
      return viaBridge("SuggestKeyPath");
    },

    /* Desktop only: updates. The browser build is served by `zcd ui` from a
     * binary the person already has on their own machine and updates with
     * `zcd update`; a page has no business replacing it, and there is no HTTP
     * fallback here on purpose rather than by omission. */
    canUpdate: function () {
      return !!(bridge && typeof bridge.UpdateStatus === "function");
    },
    updateStatus: function () {
      return viaBridge("UpdateStatus");
    },
    setUpdateCheck: function (on) {
      return viaBridge("SetUpdateCheck", on);
    },
    installUpdate: function () {
      return viaBridge("InstallUpdate");
    },
    openReleasePage: function () {
      return viaBridge("OpenReleasePage");
    },
  };

  window.Transport = Transport;
})();
