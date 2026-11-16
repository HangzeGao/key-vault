package confirmation

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kvlt/key-vault/internal/commissioning"
	"github.com/kvlt/key-vault/internal/protocol/ccsds"
	"github.com/kvlt/key-vault/internal/tpm/provider"
)

type GroundStage interface {
	ReadAnchoredGroundCommissioning(ctx context.Context, tenant string, transaction, binding, anchor [32]byte) ([]byte, error)
}

type GroundTPM interface {
	ReadCommissioningAnchor(context.Context, provider.RegisteredCommissioningAnchor) ([32]byte, error)
}

type GroundUnsealer interface {
	UnsealKey(context.Context, []byte, string) ([]byte, error)
}

// GroundResponder works against the same persistent stage and TPM as the
// provisioner. The caller binds the peer identity and both challenges to its
// authenticated maintenance session and supplies the validated authorization.
type GroundResponder struct {
	Stage GroundStage
	TPM   GroundTPM
	Keys  GroundUnsealer
}

func (g GroundResponder) Respond(ctx context.Context, tenant string, anchorRecord provider.RegisteredCommissioningAnchor,
	installation *commissioning.AuthorizedGroundInstall, t Transcript, flight Proof) (Proof, error) {
	if installation == nil || g.Stage == nil || g.TPM == nil || g.Keys == nil {
		return Proof{}, ErrConfirmation
	}
	binding := installation.Binding()
	encoded, err := t.MarshalBinary()
	if err != nil || installation.AnchorName() != anchorRecord.Name || binding.Transaction != t.Transaction ||
		binding.ProfileDigest != t.Profile || binding.DeviceID != t.Ground {
		return Proof{}, ErrConfirmation
	}
	anchor, err := g.TPM.ReadCommissioningAnchor(ctx, anchorRecord)
	if err != nil || anchor == ([32]byte{}) {
		return Proof{}, ErrConfirmation
	}
	payload, err := g.Stage.ReadAnchoredGroundCommissioning(ctx, tenant, t.Transaction, installation.RecordDigest(), anchor)
	if err != nil {
		return Proof{}, ErrConfirmation
	}
	var staged []ccsds.StagedAssociation
	if json.Unmarshal(payload, &staged) != nil || len(staged) != 3 ||
		staged[0].Association.State != ccsds.AssociationCurrent || staged[0].Association.Direction != ccsds.DirectionTCTx ||
		staged[2].Association.State != ccsds.AssociationActive || staged[2].Association.Direction != ccsds.DirectionTCRecoveryTx {
		return Proof{}, ErrConfirmation
	}
	var roots [2][]byte
	for index, entry := range [...]ccsds.StagedAssociation{staged[0], staged[2]} {
		association := entry.Association
		if association.TenantID != tenant || association.Validate() != nil || len(entry.SealedMaterial) == 0 ||
			entry.VersionID != fmt.Sprintf("%s-v%d", association.KeyID, association.KeyVersion) {
			return Proof{}, ErrConfirmation
		}
		root, err := g.Keys.UnsealKey(ctx, entry.SealedMaterial, entry.VersionID)
		defer clear(root)
		if err != nil || len(root) != 16 {
			return Proof{}, ErrConfirmation
		}
		roots[index] = root
	}
	return respond(encoded, flight, roots[0], roots[1])
}
