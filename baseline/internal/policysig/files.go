package policysig

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const maxPolicyFileBytes = 1 << 20

// TrustBundle is the public, persistent root used to verify signed policies.
// It deliberately has no private-key field.
type TrustBundle struct {
	Keys []TrustBundleKey `json:"keys"`
}

type TrustBundleKey struct {
	KeyID        string `json:"key_id"`
	Alg          string `json:"alg"`
	PublicKeyB64 string `json:"public_key_b64"`
	Status       string `json:"status"`
}

// LoadTrustBundle parses a bounded, strict JSON trust bundle.
func LoadTrustBundle(path string) (*TrustBundle, error) {
	var bundle TrustBundle
	if err := decodeFile(path, &bundle); err != nil {
		return nil, fmt.Errorf("policy: trust bundle: %w", err)
	}
	if len(bundle.Keys) == 0 {
		return nil, errors.New("policy: trust bundle contains no keys")
	}
	seen := make(map[string]struct{}, len(bundle.Keys))
	for i := range bundle.Keys {
		key := &bundle.Keys[i]
		if key.KeyID == "" || key.Alg != "Ed25519" {
			return nil, fmt.Errorf("policy: trust bundle key %d has invalid identity or algorithm", i)
		}
		if key.Status != "active" && key.Status != "revoked" {
			return nil, fmt.Errorf("policy: trust bundle key %s has invalid status", key.KeyID)
		}
		if _, duplicate := seen[key.KeyID]; duplicate {
			return nil, fmt.Errorf("policy: duplicate trust bundle key %s", key.KeyID)
		}
		seen[key.KeyID] = struct{}{}
		pub, err := decodePublicKey(key.PublicKeyB64)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("policy: trust bundle key %s is not an Ed25519 public key", key.KeyID)
		}
	}
	return &bundle, nil
}

// InstallTrustBundle adds every bundle entry to a manager.
func InstallTrustBundle(manager *Manager, bundle *TrustBundle) error {
	if manager == nil || bundle == nil {
		return errors.New("policy: nil manager or trust bundle")
	}
	for _, key := range bundle.Keys {
		pub, err := decodePublicKey(key.PublicKeyB64)
		if err != nil {
			return fmt.Errorf("policy: decode signing key %s: %w", key.KeyID, err)
		}
		if err := manager.AddTrustedSigningKey(key.KeyID, ed25519.PublicKey(pub), key.Status); err != nil {
			return err
		}
	}
	return nil
}

// LoadSignedPolicy parses one bounded, strict signed policy package.
func LoadSignedPolicy(path string) (*SignedPolicy, error) {
	var signed SignedPolicy
	if err := decodeFile(path, &signed); err != nil {
		return nil, fmt.Errorf("policy: signed package: %w", err)
	}
	return &signed, nil
}

func decodeFile(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > maxPolicyFileBytes {
		return errors.New("file must be regular and no larger than 1 MiB")
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxPolicyFileBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func decodePublicKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.RawURLEncoding.DecodeString(value)
}
