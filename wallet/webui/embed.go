package webui

import (
	"embed"
	"io/fs"
)

// The frontend, compiled into the binary. It is plain HTML, CSS and
// JavaScript with no build step and no package manager: a wallet whose
// interface is assembled from thousands of transitive dependencies
// contradicts the rest of this repository, where core/ and node/ are
// third-party-free and the whole module has two direct dependencies.
//
// Nothing here fetches from the network. The strict CSP `zcd ui` sends
// (server.go) and the one the desktop shell sets are both `default-src
// 'none'` with no external origin, so an asset that tried would fail visibly
// rather than work quietly.
//
// What no build step also removed is the parse error a build step would have
// caught for free, and for a while nothing replaced it. It is replaced now,
// and the boundary is worth stating precisely rather than leaving it to be
// discovered. assets_parse_test.go compiles each *JavaScript* file here as the
// classic script a browser will compile it as, and pins the page to the code:
// every asset index.html names exists, every script that ships is loaded, and
// every element the frontend names through $() is defined — literal ids, the
// data-panel values it dereferences, and the ids it builds by concatenation
// alike, with an unrecognised fourth form failing rather than passing
// unpinned. So a syntax error, an empty file, a renamed asset and a renamed
// element are failed tests rather than a blank wallet.
//
// index.html is NOT parsed as HTML and app.css is NOT parsed as CSS. The
// standard library has no parser for either, and importing one would be a
// third direct dependency in a module whose go.mod says the list is meant to
// stay at two; a hand-rolled tag balancer would reject the valid markup HTML's
// optional end tags allow, which is worse than no check. The id pin above is
// what covers that direction in practice — a structural break large enough to
// matter moves or drops an id — and it is a smaller claim than parsing.
//
// Nothing here is type-checked, linted or executed, and no test opens this
// page in a browser: behaviour is covered by the Go API's tests (api_test.go,
// server_test.go) and by the bridge contract in desktop/bridge_test.go, and
// not at all above that line.
//
//go:embed assets
var assets embed.FS

// Assets is the frontend rooted at the directory holding index.html.
//
// It is exported because the desktop application lives in a separate Go
// module and cannot use a go:embed directive to reach these files — embedding
// is per-package and per-directory. Handing over an fs.FS is what lets both
// front ends serve the identical bytes.
func Assets() fs.FS {
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		// Unreachable: the directive above is checked at compile time.
		panic(err)
	}
	return sub
}
