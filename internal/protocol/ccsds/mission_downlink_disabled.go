//go:build !downlink

package ccsds

import "errors"

func validateMissionDownlink(profile *MissionDownlinkProfile) error {
	if profile != nil {
		return errors.New("ccsds: downlink profile is unsupported in the TC-only build")
	}
	return nil
}

func missionDownlinkSecrets(*MissionDownlinkProfile) []byte { return nil }
