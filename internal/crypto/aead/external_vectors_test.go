package aead

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm4"
	cryptokdf "github.com/kvlt/key-vault/internal/crypto/kdf"
	cryptomac "github.com/kvlt/key-vault/internal/crypto/mac"
	"github.com/kvlt/key-vault/internal/crypto/suite"
)

const externalVectorFile = "../../../testdata/crypto/cryptography-sm4-v1.tsv"
const externalGeneratorFile = "../../../scripts/oracle/cryptography_vector_generator.py"

type externalVector struct {
	id, sourceClass, sourceReference string
	algorithm, operation             string
	key, nonce, aad, plaintext       []byte
	ciphertext, tag                  []byte
	label, context, output           []byte
	expectedStatus                   string
	generator, generatorVersion      string
}

func TestExternalOpenSourceSM4Vectors(t *testing.T) {
	vectors := loadExternalVectors(t, externalVectorFile)
	counts := map[string]int{}
	for _, vector := range vectors {
		vector := vector
		t.Run(vector.id, func(t *testing.T) {
			if vector.expectedStatus != "OK" || vector.operation != "VERIFY" {
				t.Fatalf("unexpected vector contract %q/%q", vector.operation, vector.expectedStatus)
			}
			assertExternalOracle(t, vector)
			switch vector.algorithm {
			case "SM4_BLOCK":
				block, err := sm4.NewCipher(vector.key)
				if err != nil {
					t.Fatal(err)
				}
				got := make([]byte, block.BlockSize())
				block.Encrypt(got, vector.plaintext)
				assertVectorBytes(t, "ciphertext", got, vector.ciphertext)
				block.Decrypt(got, vector.ciphertext)
				assertVectorBytes(t, "plaintext", got, vector.plaintext)
			case "SM4_CMAC":
				got, err := cryptomac.ComputeRaw(suite.SM4CMAC, vector.key, vector.plaintext)
				if err != nil {
					t.Fatal(err)
				}
				assertVectorBytes(t, "tag", got, vector.tag)
				valid, err := cryptomac.VerifyRaw(suite.SM4CMAC, vector.key, vector.plaintext, vector.tag)
				if err != nil || !valid {
					t.Fatalf("VerifyRaw() = %v, %v", valid, err)
				}
			case "SM4_GCM":
				assertCipherVector(t, suite.SM4GCM, vector)
			case "SM4_HCTR":
				assertCipherVector(t, suite.SM4HCTR, vector)
			case "SP800_108_SM4_CMAC":
				target := suite.SM4GCM
				if len(vector.output) == suite.SM4HCTR.WorkingKeyBytes() {
					target = suite.SM4HCTR
				}
				got, err := cryptokdf.CMACCounter(vector.key, target, vector.label, vector.context)
				if err != nil {
					t.Fatal(err)
				}
				assertVectorBytes(t, "output", got, vector.output)
			default:
				t.Fatalf("unsupported algorithm %q", vector.algorithm)
			}
			counts[vector.algorithm]++
		})
	}
	for algorithm, minimum := range map[string]int{
		"SM4_BLOCK": 5, "SM4_CMAC": 8, "SM4_GCM": 6,
		"SM4_HCTR": 7, "SP800_108_SM4_CMAC": 2,
	} {
		if counts[algorithm] < minimum {
			t.Fatalf("%s vector count = %d, want >= %d", algorithm, counts[algorithm], minimum)
		}
	}
}

func assertExternalOracle(t *testing.T, vector externalVector) {
	t.Helper()
	switch vector.algorithm {
	case "SM4_BLOCK", "SM4_CMAC":
		if vector.generator != "pyca-cryptography" || vector.generatorVersion != "49.0.0/OpenSSL-4.0.1" {
			t.Fatalf("unexpected cryptography oracle %q/%q", vector.generator, vector.generatorVersion)
		}
	case "SM4_GCM":
		if vector.sourceClass == "NORMATIVE" {
			if vector.generator != "RFC-8998" || vector.generatorVersion != "Appendix-A.1" {
				t.Fatalf("unexpected normative GCM oracle %q/%q", vector.generator, vector.generatorVersion)
			}
		} else if vector.generator != "pyca-cryptography" ||
			vector.generatorVersion != "49.0.0/OpenSSL-4.0.1" || vector.sourceClass != "INDEPENDENT" {
			t.Fatalf("unexpected independent GCM oracle %q/%q/%q", vector.generator, vector.generatorVersion, vector.sourceClass)
		}
	case "SM4_HCTR":
		if vector.generator != "pyca-cryptography+independent-HCTR-reference" ||
			vector.generatorVersion != "49.0.0/OpenSSL-4.0.1/profile-v1" || vector.sourceClass != "INDEPENDENT" {
			t.Fatalf("unexpected HCTR oracle %q/%q/%q", vector.generator, vector.generatorVersion, vector.sourceClass)
		}
	case "SP800_108_SM4_CMAC":
		if vector.generator != "pyca-cryptography+SP800-108-reference" ||
			vector.generatorVersion != "49.0.0/OpenSSL-4.0.1/profile-v1" || vector.sourceClass != "INDEPENDENT" {
			t.Fatalf("unexpected KDF oracle %q/%q/%q", vector.generator, vector.generatorVersion, vector.sourceClass)
		}
	default:
		t.Fatalf("unsupported algorithm %q", vector.algorithm)
	}
}

func assertCipherVector(t *testing.T, suiteID suite.ID, vector externalVector) {
	t.Helper()
	primitive, err := New(suiteID, vector.key)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, tag := primitive.Encrypt(vector.plaintext, vector.nonce, vector.aad)
	assertVectorBytes(t, "ciphertext", ciphertext, vector.ciphertext)
	assertVectorBytes(t, "tag", tag, vector.tag)
	plaintext, err := primitive.Decrypt(vector.ciphertext, vector.tag, vector.nonce, vector.aad)
	if err != nil {
		t.Fatal(err)
	}
	assertVectorBytes(t, "plaintext", plaintext, vector.plaintext)
}

func assertVectorBytes(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %x, want %x", name, got, want)
	}
}

func loadExternalVectors(t *testing.T, path string) []externalVector {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	checksumContent, err := os.ReadFile(path + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	wantChecksum := strings.Fields(string(checksumContent))
	if len(wantChecksum) != 2 || wantChecksum[1] != filepath.Base(path) {
		t.Fatalf("invalid checksum manifest %q", strings.TrimSpace(string(checksumContent)))
	}
	actualChecksum := sha256.Sum256(content)
	if hex.EncodeToString(actualChecksum[:]) != wantChecksum[0] {
		t.Fatal("external vector file SHA-256 mismatch")
	}

	var vectors []externalVector
	var generatorChecksum string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Buffer(make([]byte, 1024), 64*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "# generator_sha256=") {
			generatorChecksum = strings.TrimPrefix(line, "# generator_sha256=")
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 18 {
			t.Fatalf("vector row has %d fields, want 18", len(fields))
		}
		canonical := strings.Join(fields[:17], "\t")
		digest := sha256.Sum256([]byte(canonical))
		if hex.EncodeToString(digest[:]) != fields[17] {
			t.Fatalf("vector %q row SHA-256 mismatch", fields[0])
		}
		decode := func(index int) []byte {
			t.Helper()
			if fields[index] == "-" {
				return nil
			}
			value, err := hex.DecodeString(fields[index])
			if err != nil {
				t.Fatalf("vector %q field %d: %v", fields[0], index, err)
			}
			return value
		}
		vectors = append(vectors, externalVector{
			id: fields[0], sourceClass: fields[1], sourceReference: fields[2],
			algorithm: fields[3], operation: fields[4], key: decode(5), nonce: decode(6),
			aad: decode(7), plaintext: decode(8), ciphertext: decode(9), tag: decode(10),
			label: decode(11), context: decode(12), output: decode(13), expectedStatus: fields[14],
			generator: fields[15], generatorVersion: fields[16],
		})
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("external vector set is empty")
	}
	generatorContent, err := os.ReadFile(externalGeneratorFile)
	if err != nil {
		t.Fatal(err)
	}
	actualGeneratorChecksum := sha256.Sum256(generatorContent)
	if generatorChecksum == "" || hex.EncodeToString(actualGeneratorChecksum[:]) != generatorChecksum {
		t.Fatal("external vector generator SHA-256 mismatch")
	}
	return vectors
}
