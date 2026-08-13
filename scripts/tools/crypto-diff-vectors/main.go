package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"os"

	"github.com/kvlt/key-vault/internal/crypto/aead"
	"github.com/kvlt/key-vault/internal/crypto/suite"
	"github.com/kvlt/key-vault/internal/protocol/ccsds"
)

func main() {
	output := flag.String("output", "", "output vector file")
	cases := flag.Int("cases", 128, "number of ordinary and recovery cases")
	flag.Parse()
	if *output == "" || *cases < 1 || *cases > 10000 {
		panic("output and cases=1..10000 are required")
	}
	file, err := os.Create(*output)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	random := rand.New(rand.NewSource(0x5443534543444946))
	for index := 0; index < *cases; index++ {
		root := randomBytes(random, 16)
		spacecraft := uint16(random.Intn(1024))
		spi := uint16(random.Uint32())
		epoch := random.Uint32()
		if epoch == 0 {
			epoch = 1
		}
		version := random.Uint32()
		if version == 0 {
			version = 1
		}
		prefix := randomBytes(random, ccsds.TCNoncePrefixLength)
		iv := random.Uint32()
		plain := randomBytes(random, 16+random.Intn(241))
		working, err := ccsds.DeriveOrdinaryTrafficKey(root, spacecraft, suite.SM4HCTR, spi, epoch, version)
		if err != nil {
			panic(err)
		}
		tweak := make([]byte, 16)
		copy(tweak, prefix)
		tweak[6], tweak[7] = byte(spi>>8), byte(spi)
		tweak[8], tweak[9], tweak[10], tweak[11] = byte(iv>>24), byte(iv>>16), byte(iv>>8), byte(iv)
		primitive, err := aead.New(suite.SM4HCTR, working)
		if err != nil {
			panic(err)
		}
		ciphertext, _ := primitive.Encrypt(plain, tweak, nil)
		fmt.Fprintf(file, "O %x %04x %04x %08x %08x %x %x %x\n", root, spacecraft, spi, epoch, version, tweak, plain, ciphertext)

		recoverySPI := uint16(random.Uint32())
		recoveryVersion := random.Uint32()
		if recoveryVersion == 0 {
			recoveryVersion = 1
		}
		recovery, err := ccsds.DeriveRecoveryGCMKey(root, spacecraft, suite.SM4GCM, recoverySPI, recoveryVersion)
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(file, "R %x %04x %04x %08x %s\n", root, spacecraft, recoverySPI, recoveryVersion, hex.EncodeToString(recovery))
	}
}

func randomBytes(random *rand.Rand, length int) []byte {
	value := make([]byte, length)
	if _, err := random.Read(value); err != nil {
		panic(err)
	}
	return value
}
