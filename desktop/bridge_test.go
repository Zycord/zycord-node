package main

import (
	"os"
	"reflect"
	"regexp"
	"sort"
	"testing"
)

// The desktop bridge and the browser transport are one contract, and nothing
// in the toolchain checks it: transport.js calls Go methods by name through a
// runtime reflection bridge, so a renamed or removed method is a button that
// does nothing at runtime and a green build everywhere.
//
// This is the check. It reads the names transport.js actually calls out of
// transport.js, and asserts each one is a method on *Bridge.

var bridgeCall = regexp.MustCompile(`viaBridge\("([A-Za-z0-9_]+)"`)

func TestEveryMethodTheFrontendCallsExistsOnTheBridge(t *testing.T) {
	src, err := os.ReadFile("../wallet/webui/assets/transport.js")
	if err != nil {
		t.Fatal(err)
	}
	matches := bridgeCall.FindAllStringSubmatch(string(src), -1)
	if len(matches) < 8 {
		t.Fatalf("found only %d bridge calls in transport.js; the pattern this test reads them "+
			"with has probably stopped matching, which would make it pass by seeing nothing", len(matches))
	}

	have := map[string]bool{}
	bt := reflect.TypeOf(&Bridge{})
	for i := 0; i < bt.NumMethod(); i++ {
		have[bt.Method(i).Name] = true
	}

	var missing []string
	for _, m := range matches {
		if !have[m[1]] {
			missing = append(missing, m[1])
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("transport.js calls %v, which *Bridge does not have; in the desktop build these "+
			"are buttons that do nothing", missing)
	}
}

// TestTheBridgeIsRecognisableToTheFrontend: transport.js finds the bound
// object by looking for the two methods it is sure of, rather than by
// hard-coding window.go.<package>.<type> — which would break silently on a
// rename. That heuristic is a contract too.
func TestTheBridgeIsRecognisableToTheFrontend(t *testing.T) {
	bt := reflect.TypeOf(&Bridge{})
	for _, name := range []string{"Wallet", "Send"} {
		if _, ok := bt.MethodByName(name); !ok {
			t.Fatalf("*Bridge has no %s; transport.js uses it to recognise the bridge and would "+
				"fall back to HTTP inside an application that serves none", name)
		}
	}
}

// TestBridgeMethodsAreBindable: Wails marshals arguments and returns through
// JSON, so a bound method that takes or returns something JSON cannot carry
// is a runtime failure at the moment somebody presses the button.
func TestBridgeMethodsAreBindable(t *testing.T) {
	bt := reflect.TypeOf(&Bridge{})
	for i := 0; i < bt.NumMethod(); i++ {
		m := bt.Method(i)
		for j := 1; j < m.Type.NumIn(); j++ { // 0 is the receiver
			if !jsonShaped(m.Type.In(j)) {
				t.Errorf("%s takes %s, which does not survive the JSON bridge", m.Name, m.Type.In(j))
			}
		}
		for j := 0; j < m.Type.NumOut(); j++ {
			out := m.Type.Out(j)
			if out == reflect.TypeOf((*error)(nil)).Elem() {
				continue
			}
			if !jsonShaped(out) {
				t.Errorf("%s returns %s, which does not survive the JSON bridge", m.Name, out)
			}
		}
	}
}

func jsonShaped(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Ptr, reflect.Slice:
		return jsonShaped(t.Elem())
	case reflect.String, reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64, reflect.Struct, reflect.Map:
		return true
	default:
		return false
	}
}
