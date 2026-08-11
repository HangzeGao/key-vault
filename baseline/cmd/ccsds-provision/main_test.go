package main

import (
	"bytes"
	"testing"

	"github.com/kvlt/key-vault/internal/protocol/ccsds"
)

func TestProvisioningUsesTheSingleTCProfile(t *testing.T) {
	options := provisionOptions{tenantID: defaultTenant, currentSPI: defaultCurrentSPI,
		recoverySPI: defaultRecoverySPI, aosSPI: defaultAOSSPI, epoch: defaultEpoch, replayWindow: defaultReplay}
	profile := tcProfile()
	associations := desiredAssociations(options, profile, provisionIDs(options.tenantID))
	if len(associations) != 4 {
		t.Fatalf("association count = %d", len(associations))
	}
	for _, association := range associations {
		if err := association.Validate(); err != nil {
			t.Fatalf("association %s invalid: %v", association.ID, err)
		}
	}
	current, next, recovery, aos := associations[0], associations[1], associations[2], associations[3]
	if current.SuiteID != "SM4_HCTR" || current.State != ccsds.AssociationCurrent ||
		next.SPI != ccsds.NextSPI(current.SPI) || next.SecurityEpoch != current.SecurityEpoch+1 ||
		next.KeyID != current.KeyID || next.KeyVersion != current.KeyVersion ||
		!bytes.Equal(next.Parameters.NoncePrefix, current.Parameters.NoncePrefix) {
		t.Fatalf("ordinary Current/Next profile is inconsistent: current=%+v next=%+v", current, next)
	}
	if recovery.SuiteID != "SM4_GCM" || recovery.Parameters.TagLength != 16 {
		t.Fatalf("recovery profile = %+v", recovery)
	}
	if aos.SuiteID != "SM4_GCM" || aos.Parameters.ReplayWindow != defaultReplay || aos.Parameters.TransmittedIVLength != 12 {
		t.Fatalf("AOS profile = %+v", aos)
	}
}

func TestProvisioningAcceptsComplete16BitSPIRange(t *testing.T) {
	options := provisionOptions{tenantID: defaultTenant, currentSPI: 0xffff,
		recoverySPI: 1, aosSPI: 2, epoch: 1, replayWindow: 32}
	if err := options.validate(); err != nil {
		t.Fatalf("full-range SPI profile rejected: %v", err)
	}
	associations := desiredAssociations(options, tcProfile(), provisionIDs(options.tenantID))
	if associations[0].SPI != 0xffff || associations[1].SPI != 0x0000 {
		t.Fatalf("SPI boundary transition = 0x%04X -> 0x%04X", associations[0].SPI, associations[1].SPI)
	}

	options.recoverySPI = 0
	if err := options.validate(); err == nil {
		t.Fatal("Recovery SPI overlapping wrapped Next SPI was accepted")
	}
	options.recoverySPI = 1
	options.aosSPI = 0x10000
	if err := options.validate(); err == nil {
		t.Fatal("SPI above 0xFFFF was accepted")
	}
}

func TestProvisioningRejectsOverlappingSPIs(t *testing.T) {
	options := provisionOptions{tenantID: defaultTenant, currentSPI: 1,
		recoverySPI: 2, aosSPI: 3, epoch: 1, replayWindow: 32}
	if err := options.validate(); err == nil {
		t.Fatal("overlapping Next and Recovery SPI was accepted")
	}
}

func TestNoncePrefixesAreDeterministicAndDomainSeparated(t *testing.T) {
	tc := noncePrefix(defaultTenant, "TC-ORDINARY")
	if len(tc) != ccsds.TCNoncePrefixLength || !bytes.Equal(tc, noncePrefix(defaultTenant, "TC-ORDINARY")) {
		t.Fatalf("unexpected TC prefix %x", tc)
	}
	if bytes.Equal(tc, noncePrefix(defaultTenant, "TC-RECOVERY")) {
		t.Fatal("ordinary and Recovery nonce prefixes are not separated")
	}
}
