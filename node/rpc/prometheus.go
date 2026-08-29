package rpc

import (
	"sort"
	"strconv"
	"strings"
)

// The scrape-format rendering of /metrics (M3.5).
//
// Written here rather than pulled in, for the same reason node/ carries no
// third-party code anywhere else: the exposition format is a few hundred bytes
// of text with a published grammar, and a client library would bring a
// registry, a collector interface and a dependency tree to produce it. The
// format is the contract; the library is one way of meeting it.
//
// WHY THE JSON DID NOT SIMPLY BECOME THIS. /metrics has JSON callers already —
// the explorer's operations guide, and anything an operator wrote against it —
// and a milestone that adds scraping is not a reason to break them. The
// representation is negotiated instead: a caller that asks for the scrape
// format and not for JSON gets the exposition format, everything else keeps
// the JSON it had. `?format=` overrides both, because a human with curl wants
// to see either one without forging a header.

// promSample is one exported series.
type promSample struct {
	name string
	// kind is the TYPE line: "counter" for a monotonic total, "gauge" for a
	// value that can fall. It is not decoration — a scraper computes rates
	// from counters and would compute nonsense from a gauge labelled as one.
	kind  string
	help  string
	value uint64
	// labels is empty for most series. Sorted on render so the output of two
	// scrapes of an unchanged node is byte-identical, which is what makes a
	// diff of it meaningful.
	labels map[string]string
}

// renderProm writes the text exposition format.
//
// Series sharing a name are emitted as one contiguous group under one HELP/TYPE
// pair, which the format requires on both counts: a repeated TYPE for the same
// metric is a parse error in strict scrapers rather than a warning, and so is a
// metric family split apart by a sample of some other family in between.
//
// The grouping is performed here rather than assumed of the caller. Without it
// promSamples is correct for a reason that is not a rule — the three
// zycord_certs_total samples happen to sit next to each other in a slice
// literal — so the edit that breaks it is inserting one line into the middle
// of that literal, and what it breaks is invisible in a curl and fatal to the
// scraper this exists for. Families keep first-appearance order, so the output
// of two scrapes of an unchanged node is still byte-identical.
func renderProm(samples []promSample) []byte {
	var b strings.Builder
	order := make([]string, 0, len(samples))
	byName := make(map[string][]promSample, len(samples))
	for _, s := range samples {
		if _, ok := byName[s.name]; !ok {
			order = append(order, s.name)
		}
		byName[s.name] = append(byName[s.name], s)
	}
	grouped := make([]promSample, 0, len(samples))
	for _, name := range order {
		grouped = append(grouped, byName[name]...)
	}

	seen := map[string]bool{}
	for _, s := range grouped {
		if !seen[s.name] {
			seen[s.name] = true
			b.WriteString("# HELP " + s.name + " " + s.help + "\n")
			b.WriteString("# TYPE " + s.name + " " + s.kind + "\n")
		}
		b.WriteString(s.name)
		if len(s.labels) > 0 {
			keys := make([]string, 0, len(s.labels))
			for k := range s.labels {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			b.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					b.WriteByte(',')
				}
				b.WriteString(k + `="` + escapeLabel(s.labels[k]) + `"`)
			}
			b.WriteByte('}')
		}
		b.WriteByte(' ')
		b.WriteString(strconv.FormatUint(s.value, 10))
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// escapeLabel escapes a label value per the exposition format.
//
// Every label this node emits is a constant chosen here, so nothing hostile
// reaches it today. It is escaped anyway: the day a label carries something
// derived from the network, an unescaped quote would not be a rendering bug,
// it would be one peer able to inject series into an operator's monitoring.
func escapeLabel(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}

// wantsProm decides which representation to serve.
//
// `?format=` wins over the header so a human can ask for either with curl.
// Otherwise the Accept header decides, and the default stays JSON: a caller
// that sends nothing is a caller that existed before this function did.
//
// The header is parsed rather than searched. A substring test for
// "text/plain" hands the scrape format to the most common JSON client on the
// web: axios sends `Accept: application/json, text/plain, */*` on every
// request unless the caller overrides it, so a dashboard reading this
// endpoint's JSON through it carries those bytes without wanting what they
// select — and a node upgraded underneath that dashboard starts answering it
// with the exposition format. `application/json;charset=text/plain-ish`
// carries them too. So the header is split on ',', the parameters after ';'
// are dropped, and the media type is compared exactly.
//
// A caller that names BOTH keeps JSON. JSON is what /metrics served before the
// scrape format existed, so the burden of proof is on the header that would
// change an existing caller's answer, and naming both discharges nothing.
// q-values break the tie whenever they say something, so a lower-q text/plain
// never outranks a higher-q application/json and `text/plain;q=0.1,
// application/json;q=0.9` means what it reads as. q=0 is a refusal and is
// honoured as one.
//
// application/openmetrics-text selects the scrape format as well, because
// Prometheus lists it ahead of text/plain whenever OpenMetrics negotiation is
// on. What comes back is still the 0.0.4 text format, and that is not a
// mismatch: a scraper parses by the Content-Type of the response, which names
// its own grammar, not by what it asked for. Answering that scraper with JSON
// would be this function's own failure mode pointed the other way.
func wantsProm(format, accept string) bool {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "prometheus", "prom", "text":
		return true
	case "json":
		return false
	}
	// -1 means "the header never named it", which is not the same as q=0.
	promQ, jsonQ := -1.0, -1.0
	for _, entry := range strings.Split(accept, ",") {
		media := entry
		if i := strings.Index(media, ";"); i >= 0 {
			media = media[:i]
		}
		q := acceptQuality(entry)
		switch strings.ToLower(strings.TrimSpace(media)) {
		case "text/plain", "application/openmetrics-text":
			if q > promQ {
				promQ = q
			}
		case "application/json":
			if q > jsonQ {
				jsonQ = q
			}
		}
	}
	if promQ <= 0 {
		return false
	}
	return promQ > jsonQ
}

// acceptQuality reads one Accept entry's q-value.
//
// An entry with no q, or with a q that is not a number in [0,1], weighs 1 —
// the grammar's own default. Failing open at 1 rather than at 0 keeps a
// mangled parameter from silently demoting the media type the caller actually
// asked for; the ranking above still requires that type to beat JSON.
func acceptQuality(entry string) float64 {
	parts := strings.Split(entry, ";")
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if !strings.HasPrefix(strings.ToLower(p), "q=") {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(p[2:]), 64)
		if err != nil || v < 0 || v > 1 {
			return 1
		}
		return v
	}
	return 1
}

// promContentType is the version the format grammar is pinned to. Scrapers
// negotiate on it, and omitting the version has them guess.
const promContentType = "text/plain; version=0.0.4; charset=utf-8"
