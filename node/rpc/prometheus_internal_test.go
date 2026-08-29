package rpc

import (
	"strings"
	"testing"
)

// TestOneHelpAndTypePerMetricName pins the grouping rule.
//
// A repeated TYPE line for one metric name is a parse error in strict
// scrapers, not a warning — so a rendering that emitted HELP/TYPE per sample
// would produce output that scrapes cleanly in a curl and is rejected by the
// thing it exists for. zycord_certs_total carries three samples under one
// name, which is exactly the case that would break.
func TestOneHelpAndTypePerMetricName(t *testing.T) {
	out := string(renderProm([]promSample{
		{"zycord_certs_total", "counter", "h", 1, map[string]string{"outcome": "applied"}},
		{"zycord_certs_total", "counter", "h", 2, map[string]string{"outcome": "skipped"}},
		{"zycord_chain_height", "gauge", "h2", 7, nil},
	}))
	if got := strings.Count(out, "# TYPE zycord_certs_total"); got != 1 {
		t.Fatalf("TYPE for zycord_certs_total emitted %d times, want 1:\n%s", got, out)
	}
	if got := strings.Count(out, "# HELP zycord_certs_total"); got != 1 {
		t.Fatalf("HELP for zycord_certs_total emitted %d times, want 1:\n%s", got, out)
	}
	for _, want := range []string{
		`zycord_certs_total{outcome="applied"} 1`,
		`zycord_certs_total{outcome="skipped"} 2`,
		"zycord_chain_height 7",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// TestAMetricFamilyIsRenderedContiguously covers the half of the grouping rule
// that the HELP/TYPE count does not.
//
// The exposition format requires all samples of one metric family to arrive as
// one block, not merely under one HELP/TYPE pair. A renderer that only
// de-duplicates the header emits a valid header and an invalid body the moment
// two samples of a family are separated by a third of some other family — and
// a strict scraper rejects the whole scrape for it, while curl shows something
// that reads fine.
//
// The input here is deliberately interleaved, because promSamples today is not:
// its three zycord_certs_total entries sit next to each other in a slice
// literal, so the property holds by arrangement rather than by rule and the
// edit that breaks it is a one-line insertion nobody would look twice at.
func TestAMetricFamilyIsRenderedContiguously(t *testing.T) {
	out := string(renderProm([]promSample{
		{"zycord_certs_total", "counter", "h", 1, map[string]string{"outcome": "applied"}},
		{"zycord_chain_height", "gauge", "h2", 7, nil},
		{"zycord_certs_total", "counter", "h", 2, map[string]string{"outcome": "skipped"}},
	}))

	var families []string
	for _, line := range strings.Split(out, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := line
		if i := strings.IndexAny(name, "{ "); i >= 0 {
			name = name[:i]
		}
		if len(families) == 0 || families[len(families)-1] != name {
			families = append(families, name)
		}
	}
	seen := map[string]bool{}
	for _, name := range families {
		if seen[name] {
			t.Fatalf("%s is emitted in more than one block. The exposition format wants a "+
				"metric family delivered contiguously, and a scraper rejects the whole "+
				"scrape when it is not — which a HELP/TYPE count cannot see. It reads: %s", name, out)
		}
		seen[name] = true
	}

	// And the order between families is still first appearance, which is what
	// keeps two scrapes of an unchanged node byte-identical.
	want := []string{"zycord_certs_total", "zycord_chain_height"}
	if len(families) != len(want) || families[0] != want[0] || families[1] != want[1] {
		t.Fatalf("families rendered in order %v, want %v", families, want)
	}
}

// TestLabelRenderingIsDeterministic guards the property that makes a diff of
// two scrapes mean something: an unchanged node must render byte-identically.
// Go map iteration is deliberately randomised, so an unsorted label set would
// pass this test most of the time and fail in production monitoring.
func TestLabelRenderingIsDeterministic(t *testing.T) {
	s := []promSample{{"m", "gauge", "h", 1, map[string]string{"b": "2", "a": "1", "c": "3"}}}
	first := string(renderProm(s))
	for i := 0; i < 50; i++ {
		if got := string(renderProm(s)); got != first {
			t.Fatalf("render %d differs:\n%s\nvs\n%s", i, got, first)
		}
	}
	if !strings.Contains(first, `m{a="1",b="2",c="3"} 1`) {
		t.Errorf("labels not sorted: %s", first)
	}
}

// TestLabelValuesAreEscaped covers a hole that does not exist yet.
//
// Every label emitted today is a constant chosen in promSamples, so nothing
// hostile reaches escapeLabel. The escaping is tested anyway because the first
// label derived from network data would otherwise turn one peer into a party
// that can inject series into an operator's monitoring, and that change would
// look like a one-line addition.
func TestLabelValuesAreEscaped(t *testing.T) {
	out := string(renderProm([]promSample{
		{"m", "gauge", "h", 1, map[string]string{"k": `a"b\c` + "\n" + "d"}},
	}))
	if !strings.Contains(out, `m{k="a\"b\\c\nd"} 1`) {
		t.Fatalf("label not escaped: %q", out)
	}
	if strings.Count(out, "\n") != 3 {
		t.Fatalf("an unescaped newline split the series into extra lines:\n%q", out)
	}
}

// TestRepresentationNegotiation pins which caller gets which format: one row
// per real client that sends the header, plus rows that probe the edges no
// real client sends.
//
// The default matters most: /metrics had JSON callers before it had a scrape
// format, and a milestone that adds scraping is not a reason to break them.
// Every row in the block opening at axios's stock default header is one a
// substring test for "text/plain" got wrong, and so are the two refusal rows
// just past it — axios names both types and was answered with the scrape
// format, as was a header that spelled out `application/json;q=0.9` against
// `text/plain;q=0.1`. A test that only asserted "text/plain wins" and
// "application/json alone loses" cannot see either, because both headers name
// text/plain; what those five rows pin is the ranking between the two names
// and the exactness of the match, so each of them either names both or hides
// the bytes "text/plain" somewhere they must not count.
//
// The rows around that block carry the rest of the decision: the default, the
// headers that do select a scrape, and `?format=`. Several of them name one
// media type and nothing else on purpose, because a header that pins one
// property quietly stops pinning it once it names several — the row goes on
// evaluating the way the table says with any single one of them mishandled.
// That is why the edges — OpenMetrics, q=0, a q that will not parse — each
// get a header of their own. A lone media type only pins a weight above
// zero, though, so where the ceiling matters as well the same edge gets a
// second row that names JSON beside it.
func TestRepresentationNegotiation(t *testing.T) {
	for _, c := range []struct {
		name   string
		format string
		accept string
		want   bool
	}{
		{"no header at all keeps JSON", "", "", false},
		{"a JSON caller keeps JSON", "", "application/json", false},
		{"a curl or a Go http.Client sending */* keeps JSON", "", "*/*", false},
		{"a browser keeps JSON", "", "text/html,application/xhtml+xml,*/*;q=0.8", false},

		// The regression this table exists for. axios sets exactly this header
		// on every request unless the caller overrides it, so under a substring
		// test the single most common JSON client on the web was served the
		// exposition format by a node it had been reading JSON from.
		{"axios's stock default header keeps JSON", "", "application/json, text/plain, */*", false},
		{"a caller that ranks JSON above text keeps JSON", "", "text/plain;q=0.1, application/json;q=0.9", false},
		{"a parameter that merely contains the bytes keeps JSON", "", "application/json;charset=text/plain-ish", false},
		{"a suffix that merely contains the bytes keeps JSON", "", "application/vnd.text/plain+json", false},
		{"an explicit refusal of text/plain keeps JSON", "", "text/plain;q=0, application/json", false},
		// End of that block.

		// The row that closed it cannot pin the refusal on its own: it names
		// JSON at q=1, so the promQ > jsonQ ranking already answers JSON and
		// the q=0 guard never has to act. Alone, the ranking would say scrape,
		// since nothing outranks a type the header never mentioned — so only
		// the guard treating q=0 as a refusal keeps this row JSON.
		{"a refusal with no alternative named still keeps JSON", "", "text/plain;q=0", false},
		// The q= prefix test folds case, so an uppercase parameter name is
		// still a q-value. Every other q in this table is written lowercase,
		// so without this row dropping that fold would go unseen: `Q=0` would
		// read as an entry carrying no q at all, weigh 1, and scrape.
		{"an uppercase Q= is still a q-value, so this refuses too", "", "text/plain;Q=0", false},

		{"a bare text/plain scrapes", "", "text/plain", true},
		{"prometheus scrapes text", "", "text/plain;version=0.0.4;q=0.5,*/*;q=0.1", true},
		// Prometheus sends this once OpenMetrics negotiation is on. The body it
		// gets back is the 0.0.4 text format, which its own Content-Type names,
		// so the scraper parses what it is handed rather than what it asked for.
		{"prometheus negotiating OpenMetrics scrapes text", "",
			"application/openmetrics-text;version=1.0.0,application/openmetrics-text;version=0.0.1;q=0.75,text/plain;version=0.0.4;q=0.5,*/*;q=0.1", true},
		// That header still names text/plain further down, so it goes on
		// scraping with OpenMetrics dropped from the switch entirely. These
		// two name nothing else, and are the only rows that fail when the
		// media type stops selecting the scrape format.
		{"an OpenMetrics-only header scrapes text", "", "application/openmetrics-text", true},
		{"an OpenMetrics version parameter is still OpenMetrics", "", "application/openmetrics-text;version=1.0.0", true},
		{"a caller that ranks text above JSON scrapes", "", "application/json;q=0.2, text/plain;q=0.8", true},
		{"whitespace and case in the media type do not matter", "", "  TEXT/Plain ;q=0.9 ", true},
		// acceptQuality fails open at 1 on a q it cannot read, so a mangled
		// parameter does not silently demote the type the caller named. Every
		// other q in this table is well-formed, so failing closed at 0 instead
		// would be invisible without these — and it would not merely reorder
		// the ranking, it would trip the q=0 refusal guard.
		{"a q that is not a number scrapes rather than demoting the type", "", "text/plain;q=bogus", true},
		{"a q outside [0,1] scrapes rather than demoting the type", "", "text/plain;q=7", true},
		{"a q above 1 still outranks a q of 0.9", "", "text/plain;q=7, application/json;q=0.9", true},
		// Failing open lands at 1, not at the number that was written. The
		// rows above cannot tell 1 from 7: either outranks a type the header
		// never named, and either beats 0.9. Against an application/json
		// carrying the grammar's default q of 1, a 7 that was honoured wins.
		{"a q above 1 is not honoured as written", "", "text/plain;q=7, application/json", false},

		{"format overrides a silent header", "prometheus", "", true},
		{"format=text names the scrape format too", "text", "", true},
		{"format overrides a text header", "json", "text/plain", false},
		{"format overrides axios's header too", "prom", "application/json, text/plain, */*", true},
		{"format is case and space tolerant", " PROM ", "", true},
		{"an unknown format falls back to the header", "yaml", "text/plain", true},
	} {
		if got := wantsProm(c.format, c.accept); got != c.want {
			t.Errorf("%s: wantsProm(%q,%q)=%v want %v", c.name, c.format, c.accept, got, c.want)
		}
	}
}
