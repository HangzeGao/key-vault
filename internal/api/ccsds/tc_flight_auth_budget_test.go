package ccsds_test

import (
	"bytes"
	"context"
	"testing"
)

func TestTCFlightAuthenticationBudgetPersists(t *testing.T) {
	h := newTCFlightHarness(t)
	valid := h.protect(flightCommand)
	bad := bytes.Clone(valid)
	bad[7] ^= 1
	rewriteFECF(bad)
	p := h.flight()
	for i := 1; i <= 1024; i++ {
		r := p.receive("none", bad)
		r.require(t, "AUTHENTICATION_FAILED", nil)
		if r.CurrentAuthUsed != uint32(i*2) || r.NextAuthUsed != 0 || r.Paused {
			t.Fatal("incorrect authentication reservation", i, r)
		}
		if i == 512 {
			p.close()
			p = h.flight()
			if p.startup.CurrentAuthUsed != 1024 {
				t.Fatal("restart replenished quota")
			}
		}
	}
	p.close()
	p = h.flight()
	r := p.receive("none", valid)
	r.require(t, "AUTH_BUDGET_EXHAUSTED", nil)
	if r.Paused || r.CurrentAuthUsed != 2048 {
		t.Fatal("quota exhaustion blocked Recovery or reset budget")
	}
	p.receive("none", h.prepare()).require(t, "ROOT_PREPARED", nil)
	h.advance()
	r = p.receive("none", h.protect(flightCommand))
	r.require(t, "EPOCH_PROMOTED", flightCommand)
	if r.CurrentAuthUsed != 2 || r.NextAuthUsed != 0 {
		t.Fatal("new working key quota was not independently installed")
	}
	h.converged(r)
}

func TestTCFlightBudgetCommitRecovery(t *testing.T) {
	cases := []struct {
		name, status string
		exit         int
		committed    bool
	}{
		{"before", "PERSISTENCE_FAILED", 0, false}, {"partial", "PERSISTENCE_FAILED", 0, false},
		{"after", "STORAGE_COMMIT_UNCERTAIN", 0, true}, {"crash-before", "", 86, false},
		{"crash-partial", "", 87, false}, {"crash-after", "", 88, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTCFlightHarness(t)
			frame := h.protect(flightCommand)
			p := h.flight()
			if c.exit != 0 {
				p.crash("budget-"+c.name, frame, c.exit)
			} else {
				r := p.receive("budget-"+c.name, frame)
				r.require(t, c.status, nil)
				if r.CommitCalls != 0 || !r.Paused {
					t.Fatal("unreserved authentication was attempted")
				}
				p.close()
			}
			p = h.flight()
			expected := uint32(0)
			if c.committed {
				expected = 2
			}
			if p.startup.CurrentAuthUsed != expected {
				t.Fatal("quota recovery mismatch", p.startup.CurrentAuthUsed, expected)
			}
			r := p.receive("none", frame)
			r.require(t, "OK", flightCommand)
			if r.CurrentAuthUsed != expected+2 {
				t.Fatal("reserved attempts were reused")
			}
			p.receive("none", frame).require(t, "REPLAY_REJECTED", nil)
		})
	}
}

func TestTCFlightRepeatedWorkingKeyRotation(t *testing.T) {
	h := newTCFlightHarness(t)
	p := h.flight()
	p.receive("none", h.prepare()).require(t, "ROOT_PREPARED", nil)
	h.advance()
	r := p.receive("none", h.protect(flightCommand))
	r.require(t, "EPOCH_PROMOTED", flightCommand)
	old := h.protect(flightCommand) // counter 1, never accepted by flight.
	if err := h.service.AdvanceTCTransmitEpoch(context.Background(), "tenant-1"); err == nil {
		t.Fatal("advanced without flight confirmation")
	}
	for i := 0; i < 3; i++ {
		h.converged(r)
		if err := h.service.AdvanceTCTransmitEpoch(context.Background(), "tenant-1"); err != nil {
			t.Fatal(err)
		}
		r = p.receive("none", h.protect(flightCommand))
		r.require(t, "EPOCH_PROMOTED", flightCommand)
		if r.CurrentAuthUsed != 2 || r.NextAuthUsed != 0 {
			t.Fatal("rotation reused verification quota")
		}
	}
	p.receive("none", old).require(t, "AUTHENTICATION_FAILED", nil)
	p.close()
	p = h.flight()
	if p.startup.Epoch != 12 || p.startup.CurrentAuthUsed != 4 {
		t.Fatal("rotated state lost after restart")
	}
}
