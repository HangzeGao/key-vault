package downlink

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const vectorFile = "../../testdata/crypto/aes-downlink-v1.tsv"

func TestSharedVectors(t *testing.T) {
	var flightOutput []byte
	if path := os.Getenv("DLSEC_FLIGHT_OUTPUT"); path != "" {
		var err error
		flightOutput, err = os.ReadFile(path)
		if err != nil || len(flightOutput) != 383*DataLength {
			t.Fatal("missing or incomplete flight ciphertext stream")
		}
	}
	content, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(vectorFile + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	if string(manifest) != hex.EncodeToString(digest[:])+"  "+filepath.Base(vectorFile)+"\n" {
		t.Fatal("vector manifest mismatch")
	}
	generator, err := os.ReadFile("../../scripts/oracle/aes_downlink_vectors.py")
	if err != nil {
		t.Fatal(err)
	}
	generatorHash := sha256.Sum256(generator)
	if !strings.Contains(string(content), "# generator_sha256="+hex.EncodeToString(generatorHash[:])+"\n") {
		t.Fatal("vector generator mismatch")
	}
	normative, independent := 0, 0
	ids := map[string]bool{}
	for _, line := range strings.Split(string(content), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 18 {
			t.Fatal("invalid vector row")
		}
		rowHash := sha256.Sum256([]byte(strings.Join(fields[:17], "\t")))
		if fields[17] != hex.EncodeToString(rowHash[:]) || ids[fields[0]] {
			t.Fatal("vector row hash or identifier mismatch")
		}
		ids[fields[0]] = true
		if fields[3] != "AES_256_ECB" || fields[4] != "VERIFY" || fields[14] != "OK" ||
			fields[15] != "pyca-cryptography" || fields[16] != "50.0.2/OpenSSL-4.0.3" {
			t.Fatal("vector contract mismatch")
		}
		for _, index := range []int{6, 7, 10, 11, 12, 13} {
			if fields[index] != "-" {
				t.Fatal("unexpected vector parameter")
			}
		}
		decode := func(index int) []byte {
			value, err := hex.DecodeString(fields[index])
			if err != nil {
				t.Fatal("invalid vector hex")
			}
			return value
		}
		key, plaintext, ciphertext := decode(5), decode(8), decode(9)
		switch fields[1] {
		case "NORMATIVE":
			normative++
			if len(plaintext) != 16 || len(ciphertext) != 16 ||
				fields[2] != "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf#F.1.5" {
				t.Fatal("invalid normative block")
			}
			// ECB blocks are independent: repeat each normative block 55 times.
			plaintext, ciphertext = bytes.Repeat(plaintext, 55), bytes.Repeat(ciphertext, 55)
		case "INDEPENDENT":
			independent++
			if fields[2] != "pyca-cryptography-50.0.2/OpenSSL-4.0.3" {
				t.Fatal("invalid oracle")
			}
		default:
			t.Fatal("invalid vector source class")
		}
		if len(key) != KeyLength || len(plaintext) != DataLength || len(ciphertext) != DataLength {
			t.Fatal("invalid vector length")
		}
		if flightOutput != nil {
			actual := flightOutput[:DataLength]
			flightOutput = flightOutput[DataLength:]
			if !bytes.Equal(actual, ciphertext) {
				t.Fatal("flight ciphertext differs from oracle")
			}
			ciphertext = actual
		}
		t.Run(fields[0], func(t *testing.T) {
			keyBefore, inputBefore := bytes.Clone(key), bytes.Clone(ciphertext)
			got, err := DecryptData(key, ciphertext)
			if err != nil || !bytes.Equal(got, plaintext) {
				t.Fatal("AES downlink vector mismatch")
			}
			if !bytes.Equal(key, keyBefore) || !bytes.Equal(ciphertext, inputBefore) {
				t.Fatal("input changed")
			}
			got[0] ^= 1
			if !bytes.Equal(ciphertext, inputBefore) || !bytes.Equal(key, keyBefore) {
				t.Fatal("output aliases input")
			}
		})
	}
	if normative != 4 || independent != 379 {
		t.Fatalf("vector counts: %d normative, %d independent", normative, independent)
	}
}

func TestInvalidLengths(t *testing.T) {
	for _, length := range []int{0, 1, 16, 24, 31, 33, 64} {
		key, data := bytes.Repeat([]byte{0xa5}, length), bytes.Repeat([]byte{0x5a}, DataLength)
		output, err := DecryptData(key, data)
		if output != nil || !errors.Is(err, ErrKeyLength) || !bytes.Equal(key, bytes.Repeat([]byte{0xa5}, length)) ||
			!bytes.Equal(data, bytes.Repeat([]byte{0x5a}, DataLength)) {
			t.Fatal("invalid key accepted or modified")
		}
	}
	for _, length := range []int{0, 1, 16, 879, 881, 896, 1024} {
		data := bytes.Repeat([]byte{0x5a}, length)
		output, err := DecryptData(make([]byte, KeyLength), data)
		if output != nil || !errors.Is(err, ErrDataLength) || !bytes.Equal(data, bytes.Repeat([]byte{0x5a}, length)) {
			t.Fatal("invalid data accepted or modified")
		}
	}
}

func TestECBHasNoAuthenticationOrReplayState(t *testing.T) {
	key, data := make([]byte, KeyLength), make([]byte, DataLength)
	first, err := DecryptData(key, data)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DecryptData(key, data)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("unexpected replay enforcement")
	}
	data[0] ^= 1
	changed, err := DecryptData(key, data)
	if err != nil || bytes.Equal(first[:16], changed[:16]) || !bytes.Equal(first[16:], changed[16:]) {
		t.Fatal("unexpected ECB block or authentication behavior")
	}
}

func FuzzDecryptData(f *testing.F) {
	f.Add(make([]byte, KeyLength), make([]byte, DataLength))
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, KeyLength), make([]byte, 1024))
	f.Fuzz(func(t *testing.T, key, data []byte) {
		got, err := DecryptData(key, data)
		valid := len(key) == KeyLength && len(data) == DataLength
		if valid && (err != nil || len(got) != DataLength) || !valid && (err == nil || got != nil) {
			t.Fatal("length contract violated")
		}
	})
}
