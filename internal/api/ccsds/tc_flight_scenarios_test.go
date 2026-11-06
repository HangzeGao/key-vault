package ccsds_test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"os"
	"testing"
)

func TestTCFlightLinkFaults(t *testing.T) {
	cases := []struct {
		name, status string
		mutate       func([]byte) []byte
	}{
		{"empty", "FRAME_LENGTH_INVALID", func(b []byte) []byte { return nil }},
		{"truncated", "FRAME_LENGTH_INVALID", func(b []byte) []byte { return b[:len(b)-1] }},
		{"oversized", "FRAME_LENGTH_INVALID", func(b []byte) []byte { return append(b, make([]byte, 1025-len(b))...) }},
		{"declared-length", "FRAME_LENGTH_INVALID", func(b []byte) []byte { b[3] ^= 1; return b }},
		{"fecf-bit", "FECF_INVALID", func(b []byte) []byte { b[len(b)-1] ^= 1; return b }},
		{"ciphertext-bit", "FECF_INVALID", func(b []byte) []byte { b[11] ^= 1; return b }},
		{"unknown-spi-valid-fecf", "ASSOCIATION_NOT_FOUND", func(b []byte) []byte { binary.BigEndian.PutUint16(b[5:7], 0x4000); rewriteFECF(b); return b }},
		{"iv-jump-valid-fecf", "IV_FORWARD_JUMP_REJECTED", func(b []byte) []byte { binary.BigEndian.PutUint16(b[5:7], 0x8000|4097); rewriteFECF(b); return b }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTCFlightHarness(t)
			frame := h.protect(flightCommand)
			p := h.flight()
			before := h.snapshot()
			r := p.receive("none", c.mutate(bytes.Clone(frame)))
			r.require(t, c.status, nil)
			if r.CommitCalls != 0 || r.Paused {
				t.Fatal("wire rejection called persistence or paused healthy reception")
			}
			h.unchanged(before)
			p.close()
			p = h.flight()
			p.receive("none", frame).require(t, "OK", flightCommand)
			p.receive("none", frame).require(t, "REPLAY_REJECTED", nil)
		})
	}
}

func TestTCFlightReplayWindowAndRestart(t *testing.T) {
	h := newTCFlightHarness(t)
	frames := make([][]byte, 67)
	for i := range frames {
		frames[i] = h.protect(flightCommand)
		assertCounter(t, frames[i], uint32(i))
	}
	p := h.flight()
	p.receive("none", frames[65]).require(t, "OK", flightCommand)
	// Highest-63 is in the window; highest-64 is outside it. Unseen, in-window
	// frames can arrive out of order, but an already seen frame cannot recur.
	p.receive("none", frames[2]).require(t, "OK", flightCommand)
	p.receive("none", frames[64]).require(t, "OK", flightCommand)
	for _, i := range []int{65, 64, 2, 1, 0} {
		before := h.snapshot()
		p.receive("none", frames[i]).require(t, "REPLAY_REJECTED", nil)
		h.unchanged(before)
	}
	p.close()
	p = h.flight()
	for _, i := range []int{65, 64, 2, 1} {
		p.receive("none", frames[i]).require(t, "REPLAY_REJECTED", nil)
	}
	p.receive("none", frames[66]).require(t, "OK", flightCommand)
}

func TestTCFlightGroundRestartAndReprotect(t *testing.T) {
	h := newTCFlightHarness(t)
	p := h.flight()
	first := h.protect(flightCommand)
	assertCounter(t, first, 0)
	p.receive("none", first).require(t, "OK", flightCommand)
	// Allocate a frame whose response/transport is lost. Reopening the database
	// must retain its consumed IV; this deliberately does not rewind the counter.
	lost := h.protect(flightCommand)
	assertCounter(t, lost, 1)
	h.restartGround()
	next := h.protect(flightCommand)
	assertCounter(t, next, 2)
	if bytes.Equal(first, next) {
		t.Fatal("re-protection reused ciphertext/IV")
	}
	p.receive("none", next).require(t, "OK", flightCommand)
	p.receive("none", lost).require(t, "OK", flightCommand)
	p.receive("none", first).require(t, "REPLAY_REJECTED", nil)
	// Both new-IV frames carry the same logical command. Business execution
	// deduplication is outside crypto and must be supplied by FARM/COP-1/flight.
	p.close()
	p = h.flight()
	r := p.receive("none", next)
	r.require(t, "REPLAY_REJECTED", nil)
	h.converged(r)
}

func TestTCFlightRepeatedStorageFailures(t *testing.T) {
	for _, fault := range []string{"before", "partial"} {
		t.Run(fault, func(t *testing.T) {
			h := newTCFlightHarness(t)
			frame := h.protect(flightCommand)
			p := h.flight()
			before := h.snapshot()
			for i := 1; i <= 3; i++ {
				r := p.receive(fault, frame)
				r.require(t, "PERSISTENCE_FAILED", nil)
				if !r.Paused || r.CommitCalls != i {
					t.Fatal("failed commit did not stop reception")
				}
				blocked := p.receive("none", frame)
				blocked.require(t, "RECEPTION_PAUSED", nil)
				if blocked.CommitCalls != i {
					t.Fatal("paused receiver called persistence")
				}
				h.unchanged(before)
				p.reset().require(t, "OK", nil)
			}
			p.receive("none", frame).require(t, "OK", flightCommand)
			p.close()
			p = h.flight()
			p.receive("none", frame).require(t, "REPLAY_REJECTED", nil)
		})
	}
}

func TestTCFlightStateLoss(t *testing.T) {
	for _, mode := range []string{"missing", "truncated", "corrupt"} {
		t.Run(mode, func(t *testing.T) {
			h := newTCFlightHarness(t)
			frame := h.protect(flightCommand)
			p := h.flight()
			p.receive("none", frame).require(t, "OK", flightCommand)
			p.close()
			switch mode {
			case "missing":
				if err := os.Remove(h.state); err != nil {
					t.Fatal(err)
				}
			case "truncated":
				if err := os.WriteFile(h.state, []byte{1, 2, 3}, 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				h.corruptState()
			}
			startFlight(t, h.runner, h.vector, h.state, "STATE_INTEGRITY_FAILED")
			// Initialization must not silently commission a replacement snapshot.
			if mode == "missing" {
				if _, err := os.Stat(h.state); !os.IsNotExist(err) {
					t.Fatal("missing state was recreated")
				}
			}
		})
	}
}

func TestTCFlightOrdinaryAuthentication(t *testing.T) {
	h := newTCFlightHarness(t)
	frame := h.protect(flightCommand)
	p := h.flight()
	for _, field := range []int{4, 6, 7, 8, 9, 10, 11, len(frame) - 3} {
		bad := bytes.Clone(frame)
		bad[field] ^= 1
		rewriteFECF(bad)
		r := p.receive("none", bad)
		r.require(t, "AUTHENTICATION_FAILED", nil)
		if r.CurrentAuthUsed == 0 || r.CurrentSPI != 0x2001 || r.Pending {
			t.Fatal("authentication failure changed business state or failed to burn quota")
		}
	}
	p.receive("none", frame).require(t, "OK", flightCommand)
}

func TestTCFlightRecoveryAuthentication(t *testing.T) {
	for _, field := range []string{"header", "iv", "ciphertext", "tag", "wrong-key"} {
		t.Run(field, func(t *testing.T) {
			h := newTCFlightHarness(t)
			valid := h.prepare()
			bad := bytes.Clone(valid)
			switch field {
			case "header":
				bad[4] ^= 1
			case "iv":
				bad[10] ^= 1
			case "ciphertext":
				bad[11] ^= 1
			case "tag":
				bad[len(bad)-3] ^= 1
			case "wrong-key":
				k := h.keys["recovery"]
				k.root = bytes.Clone(k.root)
				k.root[0] ^= 1
				h.keys["recovery"] = k
				bad = h.prepare()
			}
			rewriteFECF(bad)
			p := h.flight()
			before := h.snapshot()
			r := p.receive("none", bad)
			r.require(t, "AUTHENTICATION_FAILED", nil)
			if r.CommitCalls != 0 || r.Pending {
				t.Fatal("failed authentication persisted a root or replay window")
			}
			h.unchanged(before)
			p.receive("none", valid).require(t, "ROOT_PREPARED", nil)
			p.close()
			p = h.flight()
			assertFlightState(t, p.startup, 0x2001, 8, 7, true)
		})
	}
}

func TestTCFlightNextRejection(t *testing.T) {
	for _, mode := range []string{"command", "ciphertext"} {
		t.Run(mode, func(t *testing.T) {
			h := newTCFlightHarness(t)
			old := h.protect(flightCommand)
			p := h.flight()
			p.receive("none", h.prepare()).require(t, "ROOT_PREPARED", nil)
			h.advance()
			command := bytes.Clone(flightCommand)
			if mode == "command" {
				command[6] = 3
			}
			bad := h.protect(command)
			if mode == "ciphertext" {
				bad[11] ^= 1
				rewriteFECF(bad)
			}
			before := h.snapshot()
			r := p.receive("none", bad)
			expected := "PLAINTEXT_REJECTED"
			if mode == "ciphertext" {
				expected = "AUTHENTICATION_FAILED"
			}
			r.require(t, expected, nil)
			assertFlightState(t, r, 0x2001, 8, 7, true)
			h.unchanged(before)
			// Rejecting a Next frame must leave Current usable and leave Pending intact.
			p.receive("none", old).require(t, "OK", flightCommand)
			p.close()
			p = h.flight()
			r = p.receive("none", h.protect(flightCommand))
			r.require(t, "EPOCH_PROMOTED", flightCommand)
			assertFlightState(t, r, 0x2002, 9, 8, false)
			h.converged(r)
		})
	}
}

func TestTCFlightCommitRecovery(t *testing.T) {
	faults := []struct {
		name, status string
		exit         int
		committed    bool
	}{
		{"none", "", 0, true}, {"before", "PERSISTENCE_FAILED", 0, false},
		{"partial", "PERSISTENCE_FAILED", 0, false}, {"after", "STORAGE_COMMIT_UNCERTAIN", 0, true},
		{"crash-before", "", 86, false}, {"crash-partial", "", 87, false}, {"crash-after", "", 88, true},
	}
	for _, stage := range []string{"ordinary", "prepare", "promotion"} {
		for _, fault := range faults {
			t.Run(stage+"-"+fault.name, func(t *testing.T) {
				h := newTCFlightHarness(t)
				old := h.protect(flightCommand)
				target := old
				p := h.flight()
				success := "OK"
				if stage == "prepare" {
					target = h.prepare()
					success = "ROOT_PREPARED"
				}
				if stage == "promotion" {
					p.receive("none", h.prepare()).require(t, "ROOT_PREPARED", nil)
					p.close()
					p = h.flight()
					assertFlightState(t, p.startup, 0x2001, 8, 7, true)
					h.advance()
					target = h.protect(flightCommand)
					success = "EPOCH_PROMOTED"
				}
				before := h.snapshot()
				if fault.exit != 0 {
					p.crash(fault.name, target, fault.exit)
				} else {
					expected := fault.status
					if expected == "" {
						expected = success
					}
					r := p.receive(fault.name, target)
					r.require(t, expected, successPlaintext(expected, flightCommand))
					if fault.name != "none" {
						if !r.Paused {
							t.Fatal("failed or uncertain commit did not pause")
						}
						blocked := p.receive("none", target)
						blocked.require(t, "RECEPTION_PAUSED", nil)
						if blocked.CommitCalls != r.CommitCalls {
							t.Fatal("paused receive committed")
						}
					}
					p.close()
				}
				if !fault.committed {
					h.unchanged(before)
				} else if h.snapshot() == before {
					t.Fatal("confirmed/uncertain durable commit did not publish")
				}
				h.restartGround()
				p = h.flight()
				spi, epoch, root, pending := uint16(0x2001), uint32(8), uint32(7), false
				if stage == "prepare" && fault.committed || stage == "promotion" && !fault.committed {
					pending = true
				}
				if stage == "promotion" && fault.committed {
					spi, epoch, root = 0x2002, 9, 8
				}
				assertFlightState(t, p.startup, spi, epoch, root, pending)
				h.observe(p.startup)
				expected := success
				if fault.committed {
					expected = "REPLAY_REJECTED"
				}
				r := p.receive("none", target)
				r.require(t, expected, successPlaintext(expected, flightCommand))
				if stage == "ordinary" {
					return
				}
				if stage == "prepare" {
					// The same logical prepare transaction with a fresh Recovery IV is safe.
					p.receive("none", h.prepare()).require(t, "ROOT_PREPARED", nil)
					p.close()
					p = h.flight()
					assertFlightState(t, p.startup, 0x2001, 8, 7, true)
					h.advance()
					p.receive("none", h.protect(flightCommand)).require(t, "EPOCH_PROMOTED", flightCommand)
				}
				p.receive("none", old).require(t, "ASSOCIATION_NOT_FOUND", nil)
				follow := h.protect(flightCommand)
				r = p.receive("none", follow)
				r.require(t, "OK", flightCommand)
				assertFlightState(t, r, 0x2002, 9, 8, false)
				h.converged(r)
				p.close()
				p = h.flight()
				assertFlightState(t, p.startup, 0x2002, 9, 8, false)
				p.receive("none", follow).require(t, "REPLAY_REJECTED", nil)
			})
		}
	}
}

func TestTCFlightGroundInputRejections(t *testing.T) {
	for _, mode := range []string{"invalid-base64", "unknown-field", "short-frame", "bad-fecf"} {
		t.Run(mode, func(t *testing.T) {
			h := newTCFlightHarness(t)
			body := map[string]string{"frame": base64.StdEncoding.EncodeToString(buildClearTCFrame(flightCommand))}
			switch mode {
			case "invalid-base64":
				body["frame"] = "!invalid!"
			case "unknown-field":
				body["spi"] = "2001"
			case "short-frame":
				body["frame"] = "AQ=="
			case "bad-fecf":
				frame := buildClearTCFrame(flightCommand)
				frame[len(frame)-1] ^= 1
				body["frame"] = base64.StdEncoding.EncodeToString(frame)
			}
			h.failGroundFrame(body)
			frame := h.protect(flightCommand)
			assertCounter(t, frame, 0)
			h.flight().receive("none", frame).require(t, "OK", flightCommand)
		})
	}
}
