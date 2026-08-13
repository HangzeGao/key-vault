// Command downlink-hardware-simulator creates an example raw downlink request
// from the public example Mission Security Profile and an exported DEK batch.
// It is test tooling, not a flight hardware implementation.
package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/kvlt/key-vault/internal/crypto/aead"
	"github.com/kvlt/key-vault/internal/crypto/suite"
	"github.com/kvlt/key-vault/internal/downlink"
	"github.com/kvlt/key-vault/internal/protocol/ccsds"
)

func main() {
	profilePath := flag.String("mission-profile", "", "example Mission Security Profile")
	packagePath := flag.String("dek-package", "", "exported 16417-byte DEK package")
	serial := flag.Uint("key-serial", 0, "DEK serial 0..1023")
	nonceHex := flag.String("nonce-hex", "", "explicit 12-byte hardware nonce in hexadecimal")
	plaintext := flag.String("plaintext", "example downlink payload", "example plaintext")
	flag.Parse()
	if err := run(*profilePath, *packagePath, uint16(*serial), *nonceHex, []byte(*plaintext)); err != nil {
		fmt.Fprintln(os.Stderr, "downlink-hardware-simulator:", err)
		os.Exit(1)
	}
}

func run(profilePath, packagePath string, serial uint16, nonceHex string, plaintext []byte) error {
	if profilePath == "" || packagePath == "" || int(serial) >= downlink.DEKCount {
		return errors.New("mission-profile, dek-package, and key-serial 0..1023 are required")
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil || len(nonce) != downlink.UploadNonceBytes {
		return errors.New("nonce-hex must encode exactly 12 bytes")
	}
	profileFile, err := os.Open(profilePath)
	if err != nil {
		return err
	}
	profile, err := ccsds.DecodeMissionSecurityProfile(profileFile)
	profileFile.Close()
	if err != nil {
		return err
	}
	secrets, err := profile.Secrets()
	if err != nil {
		return err
	}
	defer secrets.Zeroize()
	encodedPackage, err := os.ReadFile(packagePath)
	if err != nil {
		return err
	}
	defer zeroize(encodedPackage)
	pkg, err := downlink.ParsePackage(encodedPackage)
	if err != nil {
		return err
	}
	deks, err := pkg.Decrypt(secrets.KEKSet)
	if err != nil {
		return err
	}
	defer zeroize(deks)
	offset := int(serial) * downlink.DEKBytes
	primitive, err := aead.New(suite.SM4GCM, deks[offset:offset+downlink.DEKBytes])
	if err != nil {
		return err
	}
	ciphertext, tag := primitive.Encrypt(plaintext, nonce, nil)
	raw := make([]byte, 2, 2+len(nonce)+len(ciphertext)+len(tag))
	binary.BigEndian.PutUint16(raw, serial)
	raw = append(raw, nonce...)
	raw = append(raw, ciphertext...)
	raw = append(raw, tag...)
	response := struct {
		Package string `json:"package"`
	}{Package: base64.StdEncoding.EncodeToString(raw)}
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	return nil
}

func zeroize(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
