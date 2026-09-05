package session_test

import (
	"errors"
	"testing"

	"zycord/core/u256"
	"zycord/spec"
	"zycord/wallet"
	"zycord/wallet/session"
)

// The overspend refusal end to end, at the balance it was first measured on:
// the sender holds 1_250_000_000 drops and asks to send 999_999_999_999_999.
//
// Before the fix the wallet built it, submitted it, printed `submitted` and
// returned 0. The certificate is valid, admitted everywhere, skipped by the
// fold at any height it could be included, therefore included nowhere, and
// evicted at TTL unseen. The signer's only signal was the word `submitted`.
//
// The two amounts are the balance and the request the defect was first
// reproduced with, kept verbatim so the reproduction stays exact.
const (
	overspendHeld      = "1250000000"
	overspendRequested = 999_999_999_999_999
)

func TestOverdraftIsRefusedBeforeItIsSubmitted(t *testing.T) {
	k := testKey(t, 21)
	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	node.balance(k.Persistent(), overspendHeld)
	url := node.serve(t)

	s, err := session.New(k, spec.Mainnet(), url, "")
	if err != nil {
		t.Fatal(err)
	}
	opts := session.DefaultSendOptions()
	_, err = s.Send(testKey(t, 9).Persistent(), u256.FromUint64(overspendRequested), opts)
	if !errors.Is(err, wallet.ErrMoveExceedsBalance) {
		t.Fatalf("got %v, want ErrMoveExceedsBalance", err)
	}
	if n := node.submitCount(); n != 0 {
		t.Fatalf("a transfer the fold could only skip reached /submit %d times", n)
	}

	// The control, on the same session and the same balance: a transfer the
	// cell can actually cover still goes through. Without this the refusal
	// above could be the fixture failing for any reason at all.
	res, err := s.Send(testKey(t, 9).Persistent(), u256.FromUint64(1_000), opts)
	if err != nil {
		t.Fatalf("an affordable transfer on the same balance was refused: %v", err)
	}
	if !res.Submitted || node.submitCount() != 1 {
		t.Fatalf("expected exactly one submission, got submitted=%v count=%d", res.Submitted, node.submitCount())
	}
	if res.Underfunded != nil {
		t.Fatalf("an affordable transfer was reported as underfunded: %v", res.Underfunded)
	}
}

// TestForceOverridesTheBalanceRuleAndSaysSo.
//
// The escape hatch is for the case the wallet cannot see the future of: a
// deposit expected to land inside the TTL window makes the same certificate
// apply. Overriding must not make it silent — the preview a front end renders
// carries the refusal it swallowed, which is the half of the rule that was
// actually about trust.
func TestForceOverridesTheBalanceRuleAndSaysSo(t *testing.T) {
	k := testKey(t, 22)
	node := newMockNode(spec.Mainnet().ChainID, "zycord")
	node.balance(k.Persistent(), overspendHeld)
	url := node.serve(t)

	s, err := session.New(k, spec.Mainnet(), url, "")
	if err != nil {
		t.Fatal(err)
	}
	opts := session.DefaultSendOptions()
	opts.Force = true
	res, err := s.Send(testKey(t, 9).Persistent(), u256.FromUint64(overspendRequested), opts)
	if err != nil {
		t.Fatalf("--force did not get past the balance rule: %v", err)
	}
	if !res.Submitted || node.submitCount() != 1 {
		t.Fatalf("expected exactly one submission, got submitted=%v count=%d", res.Submitted, node.submitCount())
	}
	if !errors.Is(res.Underfunded, wallet.ErrMoveExceedsBalance) {
		t.Fatalf("the preview did not report what --force swallowed: %v", res.Underfunded)
	}
}

// TestForceBypassesNothingButTheBalanceRule.
//
// A user-facing override is only as safe as the set of things it cannot
// touch. Force is narrowed to one sentinel and the rule it names runs last in
// wallet.CheckAll, so nothing else can hide behind it. These are the two
// refusals a forced spend is most likely to want out of, and neither moves.
func TestForceBypassesNothingButTheBalanceRule(t *testing.T) {
	t.Run("the fee reserve still refuses", func(t *testing.T) {
		k := testKey(t, 23)
		node := newMockNode(spec.Mainnet().ChainID, "zycord")
		node.balance(k.Persistent(), "0")
		url := node.serve(t)
		s, err := session.New(k, spec.Mainnet(), url, "")
		if err != nil {
			t.Fatal(err)
		}
		opts := session.DefaultSendOptions()
		opts.Force = true
		_, err = s.Send(testKey(t, 9).Persistent(), u256.FromUint64(1_000), opts)
		if !errors.Is(err, wallet.ErrHeadroomExceedsBalance) {
			t.Fatalf("got %v, want the R2-H1 reserve refusal to survive --force", err)
		}
		if n := node.submitCount(); n != 0 {
			t.Fatalf("--force submitted past the reserve rule (%d submissions)", n)
		}
	})

	t.Run("the one-shot drain still needs an approval", func(t *testing.T) {
		k := testKey(t, 24)
		node := newMockNode(spec.Mainnet().ChainID, "zycord")
		node.balance(k.OneShot(), "5000000000000")
		url := node.serve(t)
		s, err := session.New(k, spec.Mainnet(), url, "")
		if err != nil {
			t.Fatal(err)
		}
		opts := session.DefaultSendOptions()
		opts.Force = true
		opts.OneShot = true
		opts.Sweep = true
		// opts.Approve deliberately left nil.
		_, err = s.Send(testKey(t, 9).Persistent(), u256.Zero, opts)
		if !errors.Is(err, session.ErrNotApproved) {
			t.Fatalf("got %v, want ErrNotApproved to survive --force", err)
		}
		if n := node.submitCount(); n != 0 {
			t.Fatalf("--force submitted an unapproved drain (%d submissions)", n)
		}
	})
}
