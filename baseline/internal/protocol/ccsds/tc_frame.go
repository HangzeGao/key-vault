package ccsds

import (
	"encoding/binary"
)

func encodeTCSecurityHeader(spi uint16, counter uint32) []byte {
	header := make([]byte, TCSecurityHeaderLength)
	binary.BigEndian.PutUint16(header[0:2], spi)
	binary.BigEndian.PutUint32(header[2:6], counter)
	return header
}

func tcInitialCounter(prefix []byte, spi uint16, counter uint32) []byte {
	initial := make([]byte, 16)
	copy(initial[0:TCNoncePrefixLength], prefix)
	binary.BigEndian.PutUint16(initial[6:8], spi)
	binary.BigEndian.PutUint32(initial[8:12], counter)
	// The final four bytes are the AES/SM4-CTR per-frame block counter and
	// start at zero, matching Go's cipher.NewCTR and the embedded C implementation.
	return initial
}

func validateTCFrame(frame []byte) error {
	if len(frame) < TCPrimaryHeaderLength+1+TCFECFLength || len(frame) > TCMaxFrameLength {
		return ErrFrameInvalid
	}
	encodedLength := int(frame[2]&0x03)<<8 | int(frame[3])
	if encodedLength+1 != len(frame) {
		return ErrFrameInvalid
	}
	want := binary.BigEndian.Uint16(frame[len(frame)-TCFECFLength:])
	if got := tcCRC16(frame[:len(frame)-TCFECFLength]); got != want {
		return ErrFrameInvalid
	}
	return nil
}

func setTCFrameLength(primaryHeader []byte, frameLength int) {
	encoded := frameLength - 1
	primaryHeader[2] = primaryHeader[2]&0xfc | byte(encoded>>8)&0x03
	primaryHeader[3] = byte(encoded)
}

func appendTCFECF(frameWithoutFECF []byte) []byte {
	out := make([]byte, len(frameWithoutFECF)+TCFECFLength)
	copy(out, frameWithoutFECF)
	binary.BigEndian.PutUint16(out[len(frameWithoutFECF):], tcCRC16(frameWithoutFECF))
	return out
}

func tcCRC16(data []byte) uint16 {
	crc := uint16(0xffff)
	for _, value := range data {
		crc ^= uint16(value) << 8
		for bit := 0; bit < 8; bit++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}
