package main

import (
	"net"
	"strings"
	"testing"
)

// This binary ships a seed list, which reverses what the tree used to say
// (bootstrapList's own comment records the reversal and what answers the two
// objections). These tests pin the parts of that reversal a reader is entitled
// to rely on: exactly one network has seeds, an operator can refuse them, and
// an operator's own addresses are never displaced by them.

// TestOnlyTheTestnetHasBuiltInSeeds is the containment. A seed handed to the
// wrong network is not a harmless extra dial: the peer refuses it at the
// handshake for a network id it does not share and scores the caller down for
// asking, so a devnet or a private --params network would spend its reputation
// on a stranger that was never going to answer.
func TestOnlyTheTestnetHasBuiltInSeeds(t *testing.T) {
	for _, c := range []struct {
		name                     string
		path                     string
		devnet, testnet, noSeeds bool
		want                     []string
	}{
		{name: "testnet", testnet: true, want: []string{testnetSeed}},
		{name: "mainnet has not launched", want: nil},
		{name: "devnet is local and throwaway", devnet: true, want: nil},
		{name: "--params is a network we know nothing about", path: "/tmp/p.json", want: nil},
		{name: "--params wins even with --testnet", path: "/tmp/p.json", testnet: true, want: nil},
		{name: "--no-seeds refuses them", testnet: true, noSeeds: true, want: nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := seedsFor(c.path, c.devnet, c.testnet, c.noSeeds)
			if len(got) != len(c.want) {
				t.Fatalf("seedsFor = %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("seedsFor = %v, want %v", got, c.want)
				}
			}
		})
	}
}

// TestTheSeedIsANameAndNotAnAddress is the change that answers "a baked-in list
// is one nobody can change when an entry goes bad". A name is repaired in a
// zone file; an address is repaired by persuading everyone to download a new
// binary. If this ever becomes a literal IP the objection comes back in full,
// so the property is asserted rather than left to a comment.
func TestTheSeedIsANameAndNotAnAddress(t *testing.T) {
	host, port, err := net.SplitHostPort(testnetSeed)
	if err != nil {
		t.Fatalf("the seed %q is not a host:port: %v", testnetSeed, err)
	}
	if net.ParseIP(host) != nil {
		t.Fatalf("the seed %q is a literal address; it must be a name so that "+
			"the address behind it can move without a release", testnetSeed)
	}
	if host == "" || !strings.Contains(host, ".") {
		t.Fatalf("the seed host %q is not a resolvable name", host)
	}
	if port == "" {
		t.Fatalf("the seed %q names no port", testnetSeed)
	}
}

// TestSeedsAreMergedAfterTheOperatorsOwnAddresses pins the order. An operator
// who names a peer chose that peer for this node; the release chose the other
// one for everybody. node/p2p seeds its store in the order it is given, so the
// order here is the order they are tried.
func TestSeedsAreMergedAfterTheOperatorsOwnAddresses(t *testing.T) {
	got, err := bootstrapList("mine.example:9421", "", []string{"seed.example:9421"})
	if err != nil {
		t.Fatalf("bootstrapList: %v", err)
	}
	want := []string{"mine.example:9421", "seed.example:9421"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// TestASeedAlreadyNamedByTheOperatorIsNotDialledTwice keeps the dedup honest
// across the new third source. Two entries for one host are not two dial
// targets, and node/p2p budgets outbound connections by count — so a duplicate
// is a slot spent on nothing.
func TestASeedAlreadyNamedByTheOperatorIsNotDialledTwice(t *testing.T) {
	got, err := bootstrapList(testnetSeed, "", []string{testnetSeed})
	if err != nil {
		t.Fatalf("bootstrapList: %v", err)
	}
	if len(got) != 1 || got[0] != testnetSeed {
		t.Fatalf("got %v, want exactly [%s]", got, testnetSeed)
	}
}

// TestNoSeedsLeavesTheOperatorsListIntact is what --no-seeds promises in its
// own help text: it removes the built-in addresses and nothing else. An
// operator refusing the project's infrastructure must not also lose the flags
// they passed, or the refusal costs them the node.
func TestNoSeedsLeavesTheOperatorsListIntact(t *testing.T) {
	got, err := bootstrapList("mine.example:9421", "",
		seedsFor("", false, true, true))
	if err != nil {
		t.Fatalf("bootstrapList: %v", err)
	}
	if len(got) != 1 || got[0] != "mine.example:9421" {
		t.Fatalf("got %v, want exactly [mine.example:9421]", got)
	}
}

// TestWithNoSourcesAtAllTheListIsEmpty is the case the startup log line exists
// for. It must stay reachable: a node with no bootstrap addresses is a
// legitimate configuration (an operator who only accepts inbound), and it must
// not be confused with a node whose seeds silently failed.
func TestWithNoSourcesAtAllTheListIsEmpty(t *testing.T) {
	got, err := bootstrapList("", "", nil)
	if err != nil {
		t.Fatalf("bootstrapList: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want an empty list", got)
	}
}
