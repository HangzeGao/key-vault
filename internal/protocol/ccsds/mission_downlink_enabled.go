//go:build downlink

package ccsds

import (
	"errors"
	"fmt"
)

func validateMissionDownlink(profile *MissionDownlinkProfile) error {
	if profile == nil {
		return errors.New("ccsds: downlink profile is required in the downlink build")
	}
	if profile.ActiveKEKSlot > 7 {
		return errors.New("ccsds: active downlink KEK slot must be 0..7")
	}
	if _, err := decodeProfileHex(profile.KEKSetHex, 128); err != nil {
		return fmt.Errorf("ccsds: invalid downlink KEK set: %w", err)
	}
	return nil
}

func missionDownlinkSecrets(profile *MissionDownlinkProfile) []byte {
	material, _ := decodeProfileHex(profile.KEKSetHex, 128)
	return material
}
