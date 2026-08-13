package keystate

import (
	"testing"
)

// TestTransitionKey covers all legal Key state transitions per design §14.
func TestTransitionKey(t *testing.T) {
	tests := []struct {
		name    string
		current KeyStatus
		event   KeyEvent
		want    KeyStatus
		wantErr bool
	}{
		{"Active -> Disabled", KeyActive, EvDisable, KeyDisabled, false},
		{"Active -> DestroyPending", KeyActive, EvScheduleDestroy, KeyDestroyPending, false},
		{"Disabled -> Active", KeyDisabled, EvEnable, KeyActive, false},
		{"Disabled -> DestroyPending", KeyDisabled, EvScheduleDestroy, KeyDestroyPending, false},
		{"DestroyPending -> Disabled (cancel)", KeyDestroyPending, EvCancelDestroy, KeyDisabled, false},
		{"DestroyPending -> Destroyed (grace)", KeyDestroyPending, EvDestroyAfterGrace, KeyDestroyed, false},
		// Illegal transitions
		{"Destroyed -> Active (terminal)", KeyDestroyed, EvEnable, KeyDestroyed, true},
		{"Destroyed -> DestroyPending (terminal)", KeyDestroyed, EvScheduleDestroy, KeyDestroyed, true},
		{"Active -> Active (no-op)", KeyActive, EvEnable, KeyActive, true},
		{"Disabled -> Disabled (no-op)", KeyDisabled, EvDisable, KeyDisabled, true},
		{"DestroyPending -> Active (illegal)", KeyDestroyPending, EvEnable, KeyDestroyPending, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TransitionKey(tt.current, tt.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("TransitionKey(%s, %s) error = %v, wantErr %v", tt.current, tt.event, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("TransitionKey(%s, %s) = %v, want %v", tt.current, tt.event, got, tt.want)
			}
		})
	}
}

// TestTransitionKV covers all legal KeyVersion state transitions per design §14.
func TestTransitionKV(t *testing.T) {
	tests := []struct {
		name    string
		current KeyVersionStatus
		event   KVEvent
		want    KeyVersionStatus
		wantErr bool
	}{
		{"PreActive -> Active (self-check)", KVPreActive, EvSelfCheckPass, KVActive, false},
		{"Active -> DecryptOnly (superseded)", KVActive, EvSupersede, KVDecryptOnly, false},
		{"Active -> Disabled", KVActive, EvKVDisable, KVDisabled, false},
		{"DecryptOnly -> Disabled", KVDecryptOnly, EvKVDisable, KVDisabled, false},
		{"Disabled -> Destroyed", KVDisabled, EvKVDestroy, KVDestroyed, false},
		// Illegal transitions
		{"Destroyed -> Active (terminal)", KVDestroyed, EvSelfCheckPass, KVDestroyed, true},
		{"PreActive -> Supersede (illegal)", KVPreActive, EvSupersede, KVPreActive, true},
		{"Disabled -> Supersede (illegal)", KVDisabled, EvSupersede, KVDisabled, true},
		{"DecryptOnly -> Destroy (must disable first)", KVDecryptOnly, EvKVDestroy, KVDecryptOnly, true},
		{"Active -> Destroy (must disable first)", KVActive, EvKVDestroy, KVActive, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TransitionKV(tt.current, tt.event)
			if (err != nil) != tt.wantErr {
				t.Errorf("TransitionKV(%s, %s) error = %v, wantErr %v", tt.current, tt.event, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("TransitionKV(%s, %s) = %v, want %v", tt.current, tt.event, got, tt.want)
			}
		})
	}
}

// TestCanEncrypt verifies CanEncrypt only allows ACTIVE keys.
func TestCanEncrypt(t *testing.T) {
	if !CanEncrypt(KeyActive) {
		t.Error("CanEncrypt(ACTIVE) should be true")
	}
	for _, s := range []KeyStatus{KeyDisabled, KeyDestroyPending, KeyDestroyed} {
		if CanEncrypt(s) {
			t.Errorf("CanEncrypt(%s) should be false", s)
		}
	}
}

// TestCanDecrypt verifies CanDecrypt allows ACTIVE, DISABLED, and DESTROY_PENDING keys.
func TestCanDecrypt(t *testing.T) {
	for _, s := range []KeyStatus{KeyActive, KeyDisabled, KeyDestroyPending} {
		if !CanDecrypt(s) {
			t.Errorf("CanDecrypt(%s) should be true", s)
		}
	}
	if CanDecrypt(KeyDestroyed) {
		t.Error("CanDecrypt(DESTROYED) should be false")
	}
}

// TestKVCanEncrypt verifies KVCanEncrypt only allows ACTIVE versions.
func TestKVCanEncrypt(t *testing.T) {
	if !KVCanEncrypt(KVActive) {
		t.Error("KVCanEncrypt(ACTIVE) should be true")
	}
	for _, s := range []KeyVersionStatus{KVPreActive, KVDecryptOnly, KVDisabled, KVDestroyed} {
		if KVCanEncrypt(s) {
			t.Errorf("KVCanEncrypt(%s) should be false", s)
		}
	}
}

// TestKVCanDecrypt is the critical test for the bug fix: DISABLED and DESTROYED
// must refuse decryption. Only ACTIVE and DECRYPT_ONLY are allowed.
// Previously, KVDisabled incorrectly returned true, violating design §6.
func TestKVCanDecrypt(t *testing.T) {
	// These should be allowed.
	if !KVCanDecrypt(KVActive) {
		t.Error("KVCanDecrypt(ACTIVE) should be true")
	}
	if !KVCanDecrypt(KVDecryptOnly) {
		t.Error("KVCanDecrypt(DECRYPT_ONLY) should be true")
	}
	// These must be refused — this is the bug we fixed.
	if KVCanDecrypt(KVDisabled) {
		t.Error("KVCanDecrypt(DISABLED) should be false — DISABLED keys must refuse decryption per design §6")
	}
	if KVCanDecrypt(KVDestroyed) {
		t.Error("KVCanDecrypt(DESTROYED) should be false")
	}
	if KVCanDecrypt(KVPreActive) {
		t.Error("KVCanDecrypt(PRE_ACTIVE) should be false")
	}
}

// TestDestroyGracePeriod verifies the grace period is 24 hours.
func TestDestroyGracePeriod(t *testing.T) {
	if DestroyGracePeriod.Hours() != 24 {
		t.Errorf("DestroyGracePeriod = %v, want 24h", DestroyGracePeriod)
	}
}
