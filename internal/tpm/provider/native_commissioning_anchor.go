package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

// RegisteredCommissioningAnchor pins the NV Name before the first write and
// the storage primary used to authenticate the TPM sessions.
type RegisteredCommissioningAnchor struct {
	Index       uint32
	Name        [2 + sha256.Size]byte
	StorageName [2 + sha256.Size]byte
}

var errCommissioningAnchor = errors.New("provider: commissioning anchor unavailable, mismatched or already committed")

var commissioningNVAttributes = tpm2.TPMANV{
	PlatformCreate: true, PolicyDelete: true, PolicyWrite: true, WriteAll: true, AuthRead: true, NoDA: true,
}

// ReadCommissioningAnchor returns zero only for the registered unwritten NV
// index. A missing, inaccessible or substituted index returns an error.
func (p *NativeProvider) ReadCommissioningAnchor(ctx context.Context, registered RegisteredCommissioningAnchor) ([32]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx.Err() != nil || p.rw == nil {
		return [32]byte{}, errCommissioningAnchor
	}
	t := transport.FromReadWriter(p.rw)
	index, written, err := readCommissioningNV(t, registered)
	if err != nil {
		return [32]byte{}, err
	}
	salt, err := readRegisteredPublic(t, tpm2.TPMHandle(nativeSRKPersistentHandle), registered.StorageName)
	if err != nil {
		return [32]byte{}, errCommissioningAnchor
	}
	return readCommissioningDigest(t, index, written, salt)
}

// CommitCommissioningAnchor permits one whole-index write and requires an
// authenticated readback. An uncertain write may be resolved by reading the
// same commitment after restart. An already committed digest is never replaced.
func (p *NativeProvider) CommitCommissioningAnchor(ctx context.Context, registered RegisteredCommissioningAnchor, digest [32]byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ctx.Err() != nil || p.rw == nil || digest == ([32]byte{}) || len(p.pcrs) == 0 {
		return errCommissioningAnchor
	}
	t := transport.FromReadWriter(p.rw)
	index, written, err := readCommissioningNV(t, registered)
	if err != nil {
		return err
	}
	salt, err := readRegisteredPublic(t, tpm2.TPMHandle(nativeSRKPersistentHandle), registered.StorageName)
	if err != nil {
		return errCommissioningAnchor
	}
	if !written {
		// Always read back. An I/O failure can mask a successful write, and
		// another authorized process may already have committed this digest.
		p.writeCommissioningDigest(t, index, salt, digest)
		index, written, err = readCommissioningNV(t, registered)
		if err != nil {
			return err
		}
	}
	actual, err := readCommissioningDigest(t, index, written, salt)
	if err != nil || actual != digest {
		return errCommissioningAnchor
	}
	return nil
}

func readCommissioningNV(t transport.TPM, registered RegisteredCommissioningAnchor) (tpm2.NamedHandle, bool, error) {
	index := tpm2.TPMHandle(registered.Index)
	if registered.Index>>24 != uint32(tpm2.TPMHTNVIndex) {
		return tpm2.NamedHandle{}, false, errCommissioningAnchor
	}
	response, err := (tpm2.NVReadPublic{NVIndex: index}).Execute(t)
	if err != nil {
		return tpm2.NamedHandle{}, false, errCommissioningAnchor
	}
	public, err := response.NVPublic.Contents()
	if err != nil || public.NVIndex != index || public.NameAlg != tpm2.TPMAlgSHA256 ||
		public.DataSize != sha256.Size || len(public.AuthPolicy.Buffer) != sha256.Size {
		return tpm2.NamedHandle{}, false, errCommissioningAnchor
	}
	actual, err := tpm2.NVName(public)
	if err != nil || !bytes.Equal(actual.Buffer, response.NVName.Buffer) {
		return tpm2.NamedHandle{}, false, errCommissioningAnchor
	}
	written := public.Attributes.Written
	public.Attributes.Written = false
	registeredName, err := tpm2.NVName(public)
	if err != nil || !bytes.Equal(registeredName.Buffer, registered.Name[:]) ||
		!bytes.Equal(tpm2.Marshal(public.Attributes), tpm2.Marshal(commissioningNVAttributes)) {
		return tpm2.NamedHandle{}, false, errCommissioningAnchor
	}
	return tpm2.NamedHandle{Handle: index, Name: *actual}, written, nil
}

func readCommissioningDigest(t transport.TPM, index tpm2.NamedHandle, written bool, salt *tpm2.TPMTPublic) ([32]byte, error) {
	response, err := (tpm2.NVRead{
		AuthHandle: tpm2.AuthHandle{Handle: index.Handle, Name: index.Name,
			Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.Salted(tpm2.TPMHandle(nativeSRKPersistentHandle), *salt))},
		NVIndex: index, Size: sha256.Size,
	}).Execute(t)
	if !written && errors.Is(err, tpm2.TPMRCNVUninitialized) {
		return [32]byte{}, nil
	}
	var digest [32]byte
	if err != nil || !written || len(response.Data.Buffer) != len(digest) {
		return digest, errCommissioningAnchor
	}
	copy(digest[:], response.Data.Buffer)
	if digest == ([32]byte{}) {
		return digest, errCommissioningAnchor
	}
	return digest, nil
}

func (p *NativeProvider) writeCommissioningDigest(t transport.TPM, index tpm2.NamedHandle, salt *tpm2.TPMTPublic, digest [32]byte) {
	session, closeSession, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16,
		tpm2.Salted(tpm2.TPMHandle(nativeSRKPersistentHandle), *salt))
	if err != nil {
		return
	}
	defer closeSession()
	if p.applyPCRPolicy(tpmutil.Handle(session.Handle())) != nil || applyCommissioningNVPolicy(t, session.Handle()) != nil {
		return
	}
	_, _ = (tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: index.Handle, Name: index.Name, Auth: session},
		NVIndex:    index, Data: tpm2.TPM2BMaxNVBuffer{Buffer: digest[:]},
	}).Execute(t)
}

func applyCommissioningNVPolicy(t transport.TPM, session tpm2.TPMHandle) error {
	if _, err := (tpm2.PolicyCommandCode{PolicySession: session, Code: tpm2.TPMCCNVWrite}).Execute(t); err != nil {
		return err
	}
	_, err := (tpm2.PolicyNVWritten{PolicySession: session, WrittenSet: false}).Execute(t)
	return err
}
