package webui_test

import (
	"bytes"
	"io/fs"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"

	"zycord/wallet/webui"
)

// Nothing else in this tree parses the wallet frontend.
//
// ~900 lines of JavaScript reach both front ends through go:embed — `zcd ui`
// serves them over loopback, the desktop shell hands the identical bytes to a
// native webview — and a syntax error in either file is a wallet that loads a
// blank page and does nothing, with `go test ./...` green, `make ci` green,
// and this package's own suite green. TestAssetsAreSelfContained
// (server_test.go) reads the assets as bytes and greps for external origins;
// desktop/bridge_test.go reads method *names* out of transport.js. Neither
// would notice an unbalanced brace around what it is reading. Nothing compiled
// the embedded JavaScript at all, and the tests below are the fix.
//
// The work is split in two. TestTheEmbeddedFrontendParses needs a JavaScript
// engine and checks that the code compiles. TestIndexLoadsTheScriptsThatParsed
// needs none, so it runs everywhere the suite runs, and checks that the page
// and the code still fit each other.

// jsSuffix is the extension that decides what gets a parse check. Discovering
// the files rather than listing them is deliberate: a third asset added later
// is covered without anybody remembering to add it here.
const jsSuffix = ".js"

// embeddedScripts returns every .js file in the embedded frontend, by path,
// with its bytes.
//
// It reads the embedded FS rather than the assets/ directory on disk, because
// the embedded bytes are the ones that ship — the two are identical by
// construction, and checking the shipped one costs nothing extra.
//
// Both tests below go through here, which is why the two checks that need no
// tooling live here rather than in the parse test: the parse test is allowed
// to skip, and neither of these may.
func embeddedScripts(t *testing.T) map[string][]byte {
	t.Helper()
	assets := webui.Assets()
	scripts := map[string][]byte{}
	err := fs.WalkDir(assets, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, jsSuffix) {
			return nil
		}
		b, err := fs.ReadFile(assets, path)
		if err != nil {
			return err
		}
		scripts[path] = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// A check that finds nothing to check passes, which is the failure mode this
	// whole file exists to close. The frontend has shipped two scripts since it
	// arrived; fewer than that means the walk stopped seeing them, not that the
	// wallet got simpler.
	if len(scripts) < 2 {
		t.Fatalf("found %d embedded %s files, want at least 2 (transport.js and app.js); "+
			"a syntax check that has nothing to check is not a check", len(scripts), jsSuffix)
	}
	// The same failure one level down. An empty file is valid JavaScript: it
	// parses, it runs, and it does nothing — so a truncated write or a `:>`
	// that got committed would sail through every engine below and ship the
	// blank wallet this file exists to prevent. Emptiness is the only content
	// judgement made here; a file that still holds code is the parser's
	// business and, past that, the API tests' and desktop/bridge_test.go's.
	for _, path := range sortedKeys(scripts) {
		if len(bytes.TrimSpace(scripts[path])) == 0 {
			t.Errorf("%s is empty. Empty JavaScript parses and does nothing, so no engine "+
				"will report this: it is a blank wallet that every test calls valid.", path)
		}
	}
	return scripts
}

func sortedKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// parseHarness compiles its stdin as a classic <script>, which is what a
// browser does with the files index.html loads, and what neither of the two
// obvious alternatives does.
//
// `node --check` is the obvious one and it is WRONG here, measurably: it
// compiles through the CommonJS module wrapper, so its grammar is a *function
// body* rather than a Script. On node 20.20.2 and 22.22.2 alike,
//
//	printf 'return;' | node --check          # exits 0
//	printf 'var a = new.target;' | node --check  # exits 0
//
// and both of those are `SyntaxError: Illegal return statement` / `new.target
// expression is not allowed here` in a browser — an app.js that never
// executes, which is exactly the defect this file is about, shipping green
// past the check meant to catch it. `--input-type=module` is wrong in the
// other direction: index.html loads these with a plain <script src>, and the
// module grammar accepts and rejects a different set of programs again.
//
// vm.Script is the Script grammar itself. It compiles — V8's pre-parser
// reports syntax errors inside function bodies too, so lazy compilation does
// not hide them — and it does not execute: the constructor returns a compiled
// script and nothing here calls runInContext. The `filename` option is what
// puts the asset's own name on the error rather than `evalmachine`.
//
// The controls in TestTheEmbeddedFrontendParses are what keep this paragraph
// honest; they fail if the harness is ever swapped back for one of the two
// alternatives above.
const parseHarness = `var vm = require("vm"), fs = require("fs");` +
	`new vm.Script(fs.readFileSync(0, "utf8"), {filename: process.argv[1] || "asset"});`

// parseAsClassicScript feeds src to the harness and reports what node said.
//
// The source goes in on stdin rather than through a temp file. node resolves
// nothing about a program it reads from a pipe, so the result cannot depend on
// a package.json that happens to sit above the temp directory on the machine
// running the test, and two assets with the same base name cannot overwrite
// each other into a check that silently covered one file instead of two.
func parseAsClassicScript(t *testing.T, node, name string, src []byte) ([]byte, error) {
	t.Helper()
	cmd := exec.Command(node, "-e", parseHarness, name)
	cmd.Stdin = bytes.NewReader(src)
	out, err := cmd.CombinedOutput()
	return out, err
}

// controls are run through the identical command path before any asset is,
// and are the answer to "what proves this check can still fail?".
//
// Without them the whole test is one `exec.Command` away from vacuous: any
// `node` on PATH that exits 0 — a stub, a wrapper, a version whose behaviour
// moved — turns it green on a wallet with an unbalanced brace in it, and the
// `node --version` line in CI would not notice, because a stub prints a
// version too. Three of the five also pin the *grammar*: they are the programs
// that separate a classic script from the CommonJS wrapper `node --check` uses
// and from an ES module, so swapping the harness for either one fails here
// with a message saying so, rather than quietly widening what ships.
var controls = []struct {
	name  string
	src   string
	parse bool
	why   string
}{
	{"positive-control.js", "var ok = 1;\n", true,
		"the harness rejects a trivially valid script, so it would reject everything and " +
			"the assets below are not being checked, they are failing. Read this as a fault " +
			"in the harness rather than in the wallet: it is the invocation itself — node, " +
			"its arguments, and the stdin pipe parseAsClassicScript writes the source down " +
			"— that has stopped working on this machine"},
	{"unbalanced-brace.js", "if (true) {\n", false,
		"an unbalanced brace is the exact defect this harness was built to catch — a " +
			"syntactically broken asset shipped inside the binary; a harness that " +
			"accepts it is not checking anything"},
	{"top-level-return.js", "var a = 1;\nreturn;\n", false,
		"a top-level `return` is legal in a CommonJS module body and illegal in a browser. " +
			"Accepting it means the harness is compiling through node's module wrapper — " +
			"`node --check` does exactly this — and is therefore checking a grammar no " +
			"front end uses"},
	{"top-level-new-target.js", "var a = new.target;\n", false,
		"`new.target` outside a function is the second program that separates the CommonJS " +
			"function-body grammar from the Script grammar a <script> tag gets"},
	{"esm-import.js", "import x from \"y\";\n", false,
		"an `import` statement means the harness moved to the module grammar, which is not " +
			"what index.html's plain <script src> asks a browser for. If index.html has " +
			"deliberately moved to type=\"module\", this control is the other half of that " +
			"change and its expectation flips with parseHarness — see the type=\"module\" " +
			"branch of TestIndexLoadsTheScriptsThatParsed"},
}

// TestTheEmbeddedFrontendParses: every JavaScript file the wallet ships is
// compiled as the classic script a browser will compile it as, and must
// compile.
//
// This is a syntax check and nothing more. It is not a linter, it executes
// nothing, and it makes no claim about behaviour: it catches the class of
// defect that ships a blank page, and says nothing about the rest. It also
// introduces no package manager — node is invoked with a program on its own
// command line, and there is no package.json, no node_modules and no
// dependency graph anywhere in this repository.
//
// It skips when node is absent, so `go test ./...` and `make ci` need no new
// toolchain on a contributor's machine — the same shape as
// TestSaveKeyFileOnAFilesystemWithoutHardLinks, which skips without hdiutil.
// A workflow used to install a pinned node so the skip could not fire on the
// runner. No workflow runs a test any more — see sim/wiring/workflow_test.go —
// so the skip is now real wherever node is missing, and this test is only run
// by someone who has node installed. The controls above are what stops that
// being worse than nothing: they are why a node that is present but WRONG fails
// loudly instead of passing, which is the failure a silent skip would hide.
func TestTheEmbeddedFrontendParses(t *testing.T) {
	scripts := embeddedScripts(t)

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skipf("node not on PATH (%v); the wallet frontend is not compiled on this machine, "+
			"so this test proves nothing here. Nothing runs it for you: install node and "+
			"re-run before pushing a change to wallet/webui/", err)
	}

	for _, c := range controls {
		out, err := parseAsClassicScript(t, node, c.name, []byte(c.src))
		switch {
		case c.parse && err != nil:
			t.Fatalf("the parse harness rejected %s:\n%s\n%s\n\nsource:\n%s",
				c.name, out, c.why, c.src)
		case !c.parse && err == nil:
			t.Fatalf("the parse harness ACCEPTED %s, which it must reject.\n%s\n\nsource:\n%s",
				c.name, c.why, c.src)
		}
	}

	for _, path := range sortedKeys(scripts) {
		out, err := parseAsClassicScript(t, node, path, scripts[path])
		if err != nil {
			t.Errorf("%s does not compile as a classic script: %v\n%s\n"+
				"This file is served to the browser wallet and embedded in the desktop "+
				"wallet unchanged. A parse error here is a blank page in both, with every "+
				"other test in this repository still green.", path, err, out)
		}
	}
}

// The shape of index.html, read with regexps rather than an HTML parser.
//
// Deliberately narrow: index.html is hand-written and stays that way (there is
// no template engine and no build step to generate anything else), so these
// are reading a file whose shape is known rather than parsing HTML in general.
// Both quote styles are accepted, because ' and " are an equally plausible
// edit in a hand-written file and a pattern that saw only one of them would go
// quiet on the other — which is the failure mode this file exists to close.
var (
	scriptTag     = regexp.MustCompile(`(?i)<script([^>]*)>`)
	srcAttr       = regexp.MustCompile(`(?i)\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	typeAttr      = regexp.MustCompile(`(?i)\btype\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	stylesheetTag = regexp.MustCompile(`(?i)<link[^>]*\brel\s*=\s*["']stylesheet["'][^>]*>`)
	hrefAttr      = regexp.MustCompile(`(?i)\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	htmlID        = regexp.MustCompile(`(?i)\bid\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	// The tab strip's link from a control to the panel it opens; the frontend
	// dereferences it with $(tab.dataset.panel).
	dataPanelAttr = regexp.MustCompile(`(?i)\bdata-panel\s*=\s*(?:"([^"]*)"|'([^']*)')`)

	// The frontend's only way of reaching an element: `function $(id) { return
	// document.getElementById(id); }` at the top of app.js. dollarCall captures
	// the argument text of every call; the three arg* patterns classify it.
	// Nested parentheses are not matched on purpose — an argument with a call
	// inside it is a fourth shape, and callSites is meant to fail on those
	// rather than guess.
	dollarCall    = regexp.MustCompile(`\$\(([^()]*)\)`)
	anyDollarCall = regexp.MustCompile(`\$\(`)
	argLiteral    = regexp.MustCompile(`^(?:"([^"]*)"|'([^']*)')$`)
	argConcat     = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*\s*\+\s*(?:"([^"]*)"|'([^']*)')$`)
	argExpression = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)
)

// idPrefixes are the prefixes the frontend concatenates an id suffix onto.
//
// This is a fact the code states, not one to be guessed at from the markup:
// app.js builds the settings and setup forms' ids as `prefix + "-key"` and
// friends, and the prefix reaches those lines from exactly two places, both
// string literals — the `[["setup", "gate"], ["settings", "panel"]]` pair list
// in fillSettingsForms, and the `configure("setup", …)` / `configure("settings",
// …)` calls in boot(). Reading it off a list is why this check has no
// threshold and no blind spot; see the comment at its use site for the
// inference it replaced and the two ways that inference was wrong.
//
// Adding a form here means adding it here. Both halves of the check below
// exist so that "means to" is enforced rather than hoped for.
var idPrefixes = []string{"setup", "settings"}

// attrValue picks the populated alternation branch out of a two-group match:
// group 1 for a double-quoted value, group 2 for a single-quoted one.
func attrValue(m []string) string {
	if m == nil {
		return ""
	}
	if m[1] != "" {
		return m[1]
	}
	return m[2]
}

// classicScriptType reports whether a <script type> value is one HTML defines
// as a classic script — the legacy JavaScript MIME types, plus the empty
// string. The list is HTML's "JavaScript MIME type essence match" set,
// narrowed to the spellings anybody would actually write; every other value
// makes the element a data block that the browser fetches and does not run.
func classicScriptType(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "text/javascript", "application/javascript", "text/ecmascript",
		"application/ecmascript":
		return true
	}
	return false
}

// TestIndexLoadsTheScriptsThatParsed: the page and the code it drives must
// still fit each other.
//
// Four failures live here, none of which needs a JavaScript engine, so this
// test runs everywhere the suite runs. Each of them is the same blank or dead
// wallet reached by a different route, and each is invisible to every other
// test in this repository.
//
//  1. A renamed or deleted asset. `zcd ui`'s file handler answers 404 for a
//     path that is not in the embedded FS, and the desktop webview does the
//     same; either way the page renders and no code runs.
//
//  2. A <script type> that is not a classic script. type="module" is the
//     interesting one: a module and a script are different grammars —
//     `import`, `export` and top-level `await` parse in one and not the other
//     — and the harness above compiles a Script. Left unchecked, that drift is
//     green here and broken in the browser, so this fails and names the
//     constant that has to move with it. Any other non-JavaScript type is a
//     simpler failure: the browser fetches the file and never runs it.
//
//  3. An embedded script the page does not load. It is either dead weight in
//     every binary or a file somebody wrote and forgot to wire up; the second
//     is a feature that silently does not exist.
//
//  4. An element the frontend reaches for that index.html does not define.
//     `$("send-button")` returns null and the first use of it throws, which
//     kills the rest of boot() — the same dead interface as a parse error,
//     from the markup side. This is the browser-side twin of
//     desktop/bridge_test.go, which pins the Go method names transport.js
//     calls; nothing else pins the element names app.js calls.
//
//     All THREE ways it names an element are pinned, not only the literal
//     one: `$("id")`, `$(tab.dataset.panel)` via the data-panel values, and
//     `$(p + "-key")` via the id families the markup declares. The first cut
//     of this test pinned literals alone and its comment claimed all of them,
//     which left twelve reachable ids — every tab panel and both settings
//     forms — resting on a sentence rather than on a check. A fourth call
//     shape fails in callSites rather than passing unpinned.
//
// What is NOT checked, said plainly rather than left to be discovered:
// index.html is never parsed as HTML and app.css is never parsed as CSS. Go's
// standard library has no HTML or CSS parser, and adding one is a third direct
// dependency in a module whose go.mod says the list is meant to stay at two. A
// hand-rolled tag balancer was considered and rejected: HTML makes end tags
// optional for several elements, so it would reject valid markup, and a rule
// that lies is worse than an absent one. Check 4 is what buys the coverage
// that matters most from that direction — a structural break big enough to
// matter almost always moves or drops an id — without pretending to parse.
func TestIndexLoadsTheScriptsThatParsed(t *testing.T) {
	scripts := embeddedScripts(t)
	assets := webui.Assets()
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		t.Fatal(err)
	}

	var loaded []string
	for _, tag := range scriptTag.FindAllStringSubmatch(string(index), -1) {
		attrs := tag[1]
		src := attrValue(srcAttr.FindStringSubmatch(attrs))
		if src == "" {
			continue // an inline <script>; there are none today, and one would need no file.
		}
		if ty := typeAttr.FindStringSubmatch(attrs); ty != nil {
			v := attrValue(ty)
			switch {
			case strings.EqualFold(strings.TrimSpace(v), "module"):
				t.Errorf("index.html loads %s with type=\"module\". A module and a classic "+
					"script are different grammars, and TestTheEmbeddedFrontendParses "+
					"compiles these files with vm.Script, which is the classic one. Move "+
					"parseHarness to the module grammar and flip the esm-import control in "+
					"the same change as this line, or the parse check goes on passing "+
					"against a grammar the browser has stopped applying.", src)
			case !classicScriptType(v):
				// Not a parse-goal problem: a type the browser does not
				// recognise as JavaScript means the element is data and the
				// file never executes at all, which lands on the same blank
				// page from the other direction.
				t.Errorf("index.html loads %s with type=%q, which no browser executes as "+
					"JavaScript; the file would be fetched and ignored.", src, v)
			}
		}
		loaded = append(loaded, src)
	}

	if len(loaded) < 2 {
		t.Fatalf("index.html loads %d scripts, want at least 2 (transport.js and app.js); "+
			"the pattern this test reads them with has probably stopped matching, which "+
			"would make it pass by seeing nothing", len(loaded))
	}

	refs := append([]string(nil), loaded...)
	styles := stylesheetTag.FindAllString(string(index), -1)
	if len(styles) < 1 {
		t.Fatalf("index.html links no stylesheet; app.css has shipped beside it for as " +
			"long as this page has had any styling at all, so this is the pattern " +
			"failing rather than the page losing its styling")
	}
	for _, tag := range styles {
		if href := attrValue(hrefAttr.FindStringSubmatch(tag)); href != "" {
			refs = append(refs, href)
		}
	}

	isLocal := func(ref string) bool {
		// Only same-directory relative references are ours to find. Anything
		// else is an external origin, which TestAssetsAreSelfContained already
		// refuses on behalf of the CSP.
		return !strings.Contains(ref, ":") && !strings.HasPrefix(ref, "/")
	}

	for _, ref := range refs {
		if !isLocal(ref) {
			continue
		}
		if _, err := fs.Stat(assets, ref); err != nil {
			t.Errorf("index.html references %q, which is not in the embedded frontend (%v). "+
				"Both front ends answer 404 for it and the page renders with nothing running.",
				ref, err)
		}
	}

	// Every script that ships is a script the page loads. The direction above
	// catches a reference with no file; this one catches a file with no
	// reference.
	loadedSet := map[string]bool{}
	for _, ref := range loaded {
		if isLocal(ref) {
			loadedSet[ref] = true
		}
	}
	for _, path := range sortedKeys(scripts) {
		if !loadedSet[path] {
			t.Errorf("%s is embedded in both wallets but index.html never loads it. It is "+
				"either dead weight in every binary or a file that was written and not "+
				"wired up, and the second is a feature that silently does not exist.", path)
		}
	}

	// The element names the frontend reaches for must exist in the page.
	//
	// `$()` is the frontend's only route to an element, and it is called three
	// ways. Each is pinned below, and callSites refuses to pass on a fourth it
	// does not recognise — without that, a new way of computing an id would be
	// unpinned and this comment would quietly stop being true, which is the
	// review finding that put the three cases here rather than one.
	defined := map[string]bool{}
	for _, m := range htmlID.FindAllStringSubmatch(string(index), -1) {
		defined[attrValue(m)] = true
	}
	if len(defined) < 20 {
		t.Fatalf("index.html defines %d element ids, want at least 20; the pattern this test "+
			"reads them with has probably stopped matching, which would make the checks "+
			"below pass by seeing nothing", len(defined))
	}

	literals, suffixes := callSites(t, scripts)

	// 1. `$("send-button")` — the literal name, checked as written.
	if len(literals) < 20 {
		t.Fatalf("the frontend asks for %d literal element ids through $(), want at least 20; "+
			"the pattern this test reads them with has probably stopped matching", len(literals))
	}
	for _, id := range literals {
		if !defined[id] {
			t.Errorf("the frontend calls $(%q) and index.html defines no such id. "+
				"getElementById returns null, the first use of it throws, and the rest of "+
				"boot() never runs — a dead interface that no other test in this "+
				"repository can see.", id)
		}
	}

	// 2. `$(tab.dataset.panel)` — the id is whatever the markup says, so the
	// markup is where it is checked: every data-panel value must name an
	// element. Renaming a panel's id without its data-panel is a tab that
	// throws on click and never opens, which is what this misses if it is
	// dropped.
	var panels []string
	for _, m := range dataPanelAttr.FindAllStringSubmatch(string(index), -1) {
		if v := attrValue(m); v != "" {
			panels = append(panels, v)
		}
	}
	if len(panels) < 3 {
		t.Fatalf("index.html declares %d data-panel values, want at least 3; the frontend "+
			"dereferences every one of them through $(tab.dataset.panel), so a pattern that "+
			"has stopped matching hides all of them", len(panels))
	}
	sort.Strings(panels)
	for _, id := range panels {
		if !defined[id] {
			t.Errorf("a tab carries data-panel=%q and index.html defines no element with that "+
				"id. The frontend calls $(tab.dataset.panel) on click: null, a throw, and a "+
				"tab that never opens.", id)
		}
	}

	// 3. `$(p + "-key")` — the id is built from a prefix and a suffix, and the
	// two files have to agree about the whole name. The suffixes are read out
	// of the code (callSites). The prefixes are idPrefixes, written down.
	//
	// Written down, and not inferred from the shape of index.html, because the
	// code states them literally — twice — and a fact stated in the source
	// beats anything reconstructed from the markup around it:
	//
	//	fillSettingsForms:  [["setup", "gate"], ["settings", "panel"]].forEach(…)
	//	boot:               configure("setup", gateError)
	//	boot:               configure("settings", …)
	//
	// (Cited by function, not by line: line numbers rot silently, and one of
	// these three was already off by one when it was written.)
	//
	// The inference that stood here before — "a prefix is a family when it heads
	// some literal $() id and the markup carries two or more of the suffixes" —
	// went silent on a real defect, and the floor on the family count was the
	// only thing that had been hiding it. Measured, not argued: add a complete
	// third family (`vault-key`, `-rpc`, `-network`, `-confirm` in index.html
	// AND a literal $("vault-…") call in app.js, because the old rule needed
	// both halves before it would count one), then rename settings-key,
	// settings-rpc and settings-network. `settings` drops under the threshold
	// and stops being a family, the count is still two, the test says ok — and
	// configure("settings") reads .value off three nulls, so the settings form
	// cannot be saved. The floor only worked while two families were all there
	// were.
	//
	// A list has no threshold, so it has no such day. What a list on its own
	// does not have is the inference's one real virtue: reach over families
	// nobody wrote down. That is what the reverse direction below is for, and
	// it is why it keeps both of the old rule's halves — two shared suffixes in
	// the markup AND a prefix the code names — while using them to demand a
	// listing rather than to validate one.
	//
	// The list is pinned from both ends, so it cannot rot:
	//
	//   - every prefix in it must still head some literal $("…") id in the
	//     frontend, so an entry here cannot go on pinning ids for a form the
	//     code has dropped. `setup` is attested by $("setup-key") and
	//     $("setup-browse"), `settings` by three more, so this survives an
	//     ordinary edit and fails on a deletion;
	//   - every prefix the code names that index.html has grown TWO or more of
	//     the suffixed ids for must be in the list. Two, not a complete set,
	//     because a complete set is precisely the state a defect destroys: an
	//     unlisted `recover` form whose key input is typoed `recover-oops` is
	//     never complete, so a completeness bar would let the whole family
	//     through unpinned. And the code half is not optional either: without
	//     it, `<div id="node-rpc">` beside `<div id="node-network">` in a status
	//     panel clears the threshold and this would demand a form that does not
	//     exist — the failure the old rule's code half was there to prevent,
	//     and it is kept here for the same reason.
	if len(suffixes) < 2 {
		t.Fatalf("the frontend builds element ids from %d distinct suffixes, want at least 2; "+
			"the pattern this test reads them with has probably stopped matching", len(suffixes))
	}

	// codeKnown is the set of prefixes the frontend itself names: the head of
	// every literal $("…") id it asks for. It is the "the code attests it" half
	// of the old inference, and it is kept — for the reverse direction only —
	// because a threshold without it fabricates form families out of ordinary
	// markup. `<div id="node-rpc">` beside `<div id="node-network">` in a node
	// status panel is two shared suffixes and is not a form; `node` heads no
	// literal $() id, so it is not a family and this says nothing about it.
	codeKnown := map[string]bool{}
	for _, id := range literals {
		if i := strings.Index(id, "-"); i > 0 {
			codeKnown[id[:i]] = true
		}
	}
	if len(codeKnown) < 4 {
		t.Fatalf("only %d id prefixes are named in the frontend's literal $() calls, want at "+
			"least 4; the split this test reads them with has probably stopped matching, "+
			"which would make both directions of the idPrefixes check pass by seeing nothing",
			len(codeKnown))
	}

	for _, prefix := range idPrefixes {
		if !codeKnown[prefix] {
			t.Errorf("idPrefixes lists %q and the frontend no longer asks for a single "+
				"literal id starting %q-. Either the form was renamed and this list did not "+
				"move with it, or the form is gone and the list is pinning ids nobody "+
				"builds.", prefix, prefix)
			continue
		}
		for _, sfx := range suffixes {
			if id := prefix + sfx; !defined[id] {
				t.Errorf("the frontend builds the id %q — it concatenates %q onto the "+
					"prefix %q and reads .value off the result with no null guard — and "+
					"index.html defines no such element: null, a throw, and a form that "+
					"cannot be saved.", id, sfx, prefix)
			}
		}
	}

	listed := map[string]bool{}
	for _, prefix := range idPrefixes {
		listed[prefix] = true
	}
	var unlisted []string
	carried := map[string][]string{}
	for prefix := range codeKnown {
		if listed[prefix] {
			continue
		}
		var got []string
		for _, sfx := range suffixes {
			if defined[prefix+sfx] {
				got = append(got, sfx)
			}
		}
		if len(got) >= 2 {
			unlisted = append(unlisted, prefix)
			carried[prefix] = got
		}
	}
	sort.Strings(unlisted)
	for _, prefix := range unlisted {
		t.Errorf("index.html defines %v for the prefix %q, the frontend asks for a literal "+
			"id starting %q-, and idPrefixes does not list it. Two shared suffixes under a "+
			"prefix the code itself names is the shape of a form family, and an unlisted "+
			"family is one whose ids nothing pins — including the one it is missing, which "+
			"is how a typoed id ships. Add %q to idPrefixes if it is a form, and the check "+
			"above will then name any id it lacks; rename these ids if the resemblance is a "+
			"coincidence.", carried[prefix], prefix, prefix, prefix)
	}
}

// callSites reads every $() call in the frontend and returns the literal ids it
// asks for and the suffixes it concatenates onto a prefix.
//
// It is also the guard that keeps TestIndexLoadsTheScriptsThatParsed's claim
// true as the code changes. Three call shapes are known — a string literal, a
// bare expression (`$(tab.dataset.panel)`), and identifier + string literal —
// and each has a check built for it. A fourth shape is not something to guess
// about: it fails here and names itself, so whoever writes it decides how it
// gets pinned instead of discovering years later that it never was.
func callSites(t *testing.T, scripts map[string][]byte) (literals, suffixes []string) {
	t.Helper()
	seenLiteral, seenSuffix := map[string]bool{}, map[string]bool{}
	for _, path := range sortedKeys(scripts) {
		src := string(scripts[path])
		// dollarCall cannot match an argument that contains parentheses of its
		// own, so a call like $(foo(bar)) would not be skipped loudly — it
		// would not be seen at all. Counting every `$(` and requiring the
		// classifier to have reached all of them is what turns that silence
		// into a failure.
		if seen, all := len(dollarCall.FindAllStringIndex(src, -1)), len(anyDollarCall.FindAllStringIndex(src, -1)); seen != all {
			t.Errorf("%s has %d $() calls and this test could read the arguments of only %d. "+
				"The unread ones have parentheses inside them, and an element id this test "+
				"never sees is an id nothing pins to index.html.\n"+
				"This counts text, not syntax, so a `$(` inside a comment or a string "+
				"literal reaches it too — a `$(foo(bar))` written in prose is a real "+
				"failure here and the fix is to reword the line. The direction is the safe "+
				"one: an unreadable call can only ever fail loudly, never pass unseen.",
				path, all, seen)
		}
		for _, loc := range dollarCall.FindAllStringSubmatchIndex(src, -1) {
			// `function $(id) {` is the definition, not a call.
			if loc[0] >= len("function ") && src[loc[0]-len("function "):loc[0]] == "function " {
				continue
			}
			arg := strings.TrimSpace(src[loc[2]:loc[3]])
			switch {
			case argLiteral.MatchString(arg):
				// No `v != ""` guard: $("") is a call that reaches for an
				// element, so it is pinned like any other and fails against an
				// index.html that (necessarily) defines no empty id. Dropping
				// it here would be an unpinned $() call in the file written to
				// make sure there are none.
				if v := attrValue(argLiteral.FindStringSubmatch(arg)); !seenLiteral[v] {
					seenLiteral[v] = true
					literals = append(literals, v)
				}
			case argConcat.MatchString(arg):
				// An empty suffix is dropped rather than recorded: `prefix + ""`
				// names the prefix itself, and feeding "" to the family loops
				// below would make every word its own family. It builds no id
				// this test can pin, and it is not a shape worth failing on.
				if v := attrValue(argConcat.FindStringSubmatch(arg)); v != "" && !seenSuffix[v] {
					seenSuffix[v] = true
					suffixes = append(suffixes, v)
				}
			case argExpression.MatchString(arg):
				// `$(tab.dataset.panel)`: the id lives in the markup, and the
				// data-panel check above is what pins it.
			default:
				t.Errorf("%s calls $(%s), which is a way of naming an element this test does "+
					"not know how to check. Every id the frontend reaches for is pinned to "+
					"index.html; add the case rather than leaving this one unpinned, or the "+
					"element it names can be renamed away without a single test noticing.",
					path, arg)
			}
		}
	}
	sort.Strings(literals)
	sort.Strings(suffixes)
	return literals, suffixes
}
