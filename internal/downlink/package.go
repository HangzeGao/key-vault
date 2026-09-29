//go:build downlink

package downlink

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/kvlt/key-vault/internal/crypto/aead"
	"github.com/kvlt/key-vault/internal/crypto/suite"
)

const (
	KEKSlots           = 8
	KEKBytes           = 16
	KEKSetBytes        = KEKSlots * KEKBytes
	DEKCount           = 1024
	DEKBytes           = 16
	DEKSetBytes        = DEKCount * DEKBytes
	UploadNonceBytes   = 12
	GCMTagBytes        = 16
	PackageHeaderBytes = 5
	PackageBytes       = PackageHeaderBytes + UploadNonceBytes + DEKSetBytes + GCMTagBytes
)

var (
	ErrNotProvisioned = errors.New("downlink: key set is not provisioned")
	ErrNotObserved    = errors.New("downlink: current batch has not been observed")
	ErrAuthentication = errors.New("downlink: authentication failed")
	ErrInvalid        = errors.New("downlink: invalid input")
)

type Package struct {
	KEKSlot    uint8
	Generation uint32
	Nonce      [UploadNonceBytes]byte
	Ciphertext [DEKSetBytes]byte
	Tag        [GCMTagBytes]byte
}

func EncryptPackage(kekSet, deks []byte, slot uint8, generation uint32) (*Package, error) {
	if len(kekSet) != KEKSetBytes || len(deks) != DEKSetBytes || slot >= KEKSlots || generation == 0 {
		return nil, ErrInvalid
	}
	var result Package
	result.KEKSlot = slot
	result.Generation = generation
	if _, err := randomRead(result.Nonce[:]); err != nil {
		return nil, err
	}
	primitive, err := aead.New(suite.SM4GCM, kekSet[int(slot)*KEKBytes:int(slot+1)*KEKBytes])
	if err != nil {
		return nil, err
	}
	encodedHeader := result.header()
	ciphertext, tag := primitive.Encrypt(deks, result.Nonce[:], encodedHeader[:])
	copy(result.Ciphertext[:], ciphertext)
	copy(result.Tag[:], tag)
	return &result, nil
}

func (p Package) Decrypt(kekSet []byte) ([]byte, error) {
	if len(kekSet) != KEKSetBytes || p.KEKSlot >= KEKSlots || p.Generation == 0 {
		return nil, ErrInvalid
	}
	primitive, err := aead.New(suite.SM4GCM, kekSet[int(p.KEKSlot)*KEKBytes:int(p.KEKSlot+1)*KEKBytes])
	if err != nil {
		return nil, err
	}
	header := p.header()
	plaintext, err := primitive.Decrypt(p.Ciphertext[:], p.Tag[:], p.Nonce[:], header[:])
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

func (p Package) MarshalBinary() []byte {
	encoded := make([]byte, PackageBytes)
	header := p.header()
	copy(encoded[:PackageHeaderBytes], header[:])
	copy(encoded[PackageHeaderBytes:PackageHeaderBytes+UploadNonceBytes], p.Nonce[:])
	copy(encoded[PackageHeaderBytes+UploadNonceBytes:PackageBytes-GCMTagBytes], p.Ciphertext[:])
	copy(encoded[PackageBytes-GCMTagBytes:], p.Tag[:])
	return encoded
}

func ParsePackage(encoded []byte) (*Package, error) {
	if len(encoded) != PackageBytes {
		return nil, ErrInvalid
	}
	var result Package
	result.KEKSlot = encoded[0]
	result.Generation = binary.BigEndian.Uint32(encoded[1:5])
	if result.KEKSlot >= KEKSlots || result.Generation == 0 {
		return nil, ErrInvalid
	}
	copy(result.Nonce[:], encoded[5:17])
	copy(result.Ciphertext[:], encoded[17:PackageBytes-GCMTagBytes])
	copy(result.Tag[:], encoded[PackageBytes-GCMTagBytes:])
	return &result, nil
}

func Digest(encoded []byte) [32]byte { return sha256.Sum256(encoded) }

func (p Package) header() [PackageHeaderBytes]byte {
	var header [PackageHeaderBytes]byte
	header[0] = p.KEKSlot
	binary.BigEndian.PutUint32(header[1:], p.Generation)
	return header
}

func GenerateDEKSet() ([]byte, error) {
	deks := make([]byte, DEKSetBytes)
	if _, err := randomRead(deks); err != nil {
		zeroize(deks)
		return nil, err
	}
	return deks, nil
}

var randomRead = rand.Read

func zeroize(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
