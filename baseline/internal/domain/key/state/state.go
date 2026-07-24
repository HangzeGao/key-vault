// Package keystate implements the Key and KeyVersion state machines per
// design §14. State transitions are pure functions; persistence is the
// repository's responsibility. This centralization is required by HA-06.
package keystate

import (
	"fmt"
	"time"
)

// KeyStatus enumerates Key states.
type KeyStatus string

const (
	KeyActive         KeyStatus = "ACTIVE"
	KeyDisabled       KeyStatus = "DISABLED"
	KeyDestroyPending KeyStatus = "DESTROY_PENDING"
	KeyDestroyed      KeyStatus = "DESTROYED"
)

// KeyVersionStatus enumerates KeyVersion states.
type KeyVersionStatus string

const (
	KVPreActive   KeyVersionStatus = "PRE_ACTIVE"
	KVActive      KeyVersionStatus = "ACTIVE"
	KVDecryptOnly KeyVersionStatus = "DECRYPT_ONLY"
	KVDisabled    KeyVersionStatus = "DISABLED"
	KVDestroyed   KeyVersionStatus = "DESTROYED"
)

// KeyEvent is a trigger for a Key state transition.
type KeyEvent string

const (
	EvDisable           KeyEvent = "disable"
	EvEnable            KeyEvent = "enable"
	EvScheduleDestroy   KeyEvent = "schedule_destroy"
	EvCancelDestroy     KeyEvent = "cancel_destroy"
	EvDestroyAfterGrace KeyEvent = "destroy_after_grace"
)

// KVEvent is a trigger for a KeyVersion state transition.
type KVEvent string

const (
	EvSelfCheckPass KVEvent = "self_check_pass"
	EvSupersede     KVEvent = "supersede"
	EvKVDisable     KVEvent = "disable"
	EvKVDestroy     KVEvent = "destroy"
)

// TransitionKey returns the new Key status for a (current, event) pair,
// or an error if the transition is illegal. Pure function.
func TransitionKey(current KeyStatus, event KeyEvent) (KeyStatus, error) {
	switch current {
	case KeyActive:
		switch event {
		case EvDisable:
			return KeyDisabled, nil
		case EvScheduleDestroy:
			return KeyDestroyPending, nil
		}
	case KeyDisabled:
		switch event {
		case EvEnable:
			return KeyActive, nil
		case EvScheduleDestroy:
			return KeyDestroyPending, nil
		}
	case KeyDestroyPending:
		switch event {
		case EvCancelDestroy:
			return KeyDisabled, nil
		case EvDestroyAfterGrace:
			return KeyDestroyed, nil
		}
	case KeyDestroyed:
		// Terminal.
	}
	return current, fmt.Errorf("keystate: illegal transition %s -> %s", current, event)
}

// TransitionKV returns the new KeyVersion status for a (current, event) pair.
func TransitionKV(current KeyVersionStatus, event KVEvent) (KeyVersionStatus, error) {
	switch current {
	case KVPreActive:
		switch event {
		case EvSelfCheckPass:
			return KVActive, nil
		}
	case KVActive:
		switch event {
		case EvSupersede:
			return KVDecryptOnly, nil
		case EvKVDisable:
			return KVDisabled, nil
		}
	case KVDecryptOnly:
		switch event {
		case EvKVDisable:
			return KVDisabled, nil
		}
	case KVDisabled:
		switch event {
		case EvKVDestroy:
			return KVDestroyed, nil
		}
	case KVDestroyed:
		// Terminal.
	}
	return current, fmt.Errorf("keystate: illegal transition %s -> %s", current, event)
}

// CanEncrypt returns whether a key in the given status may be used for new encryption.
func CanEncrypt(s KeyStatus) bool {
	return s == KeyActive
}

// CanDecrypt returns whether a key in the given status may be used for decryption.
func CanDecrypt(s KeyStatus) bool {
	switch s {
	case KeyActive, KeyDisabled, KeyDestroyPending:
		return true
	}
	return false
}

// KVCanEncrypt returns whether a key version may be used for new encryption.
func KVCanEncrypt(s KeyVersionStatus) bool {
	return s == KVActive
}

// KVCanDecrypt returns whether a key version may be used for decryption.
// Per design §6 and §9.5, DISABLED and DESTROYED refuse decryption.
func KVCanDecrypt(s KeyVersionStatus) bool {
	switch s {
	case KVActive, KVDecryptOnly:
		return true
	}
	return false
}

// DestroyGracePeriod is the baseline cool-down period before a DESTROY_PENDING
// key transitions to DESTROYED.
const DestroyGracePeriod = 24 * time.Hour
