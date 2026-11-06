package ccsds

import (
	"encoding/binary"
)

func encodeRecoverySecurityHeader(counter uint32) []byte {
	header := make([]byte, 6)
	binary.BigEndian.PutUint16(header[:2], 0xc000)
	binary.BigEndian.PutUint32(header[2:], counter)
	return header
}
func encodeOrdinaryControl(epoch, counter uint32) []byte {
	control := make([]byte, 2)
	binary.BigEndian.PutUint16(control, uint16(epoch%3)<<14|uint16(counter))
	return control
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

func splitPlainTCFrame(frame []byte, maxFrameLength int) (primaryHeader, data []byte, err error) {
	if validateTCFrame(frame) != nil || len(frame)+TCSecurityHeaderLength > TCMaxFrameLength ||
		len(frame)+TCSecurityHeaderLength > maxFrameLength {
		return nil, nil, ErrFrameInvalid
	}
	dataLength := len(frame) - TCPrimaryHeaderLength - TCFECFLength
	if dataLength < 16 {
		return nil, nil, ErrFrameInvalid
	}
	return append([]byte(nil), frame[:TCPrimaryHeaderLength]...),
		append([]byte(nil), frame[TCPrimaryHeaderLength:len(frame)-TCFECFLength]...), nil
}

func prepareTCPrimaryHeader(template []byte, payloadLength, maxFrameLength int) ([]byte, error) {
	frameLength := TCPrimaryHeaderLength + payloadLength + TCFECFLength
	if len(template) != TCPrimaryHeaderLength || payloadLength < 1 ||
		frameLength > TCMaxFrameLength || frameLength > maxFrameLength {
		return nil, ErrFrameInvalid
	}
	header := append([]byte(nil), template...)
	setTCFrameLength(header, frameLength)
	return header, nil
}

func assembleTCFrame(primaryHeader, payload []byte, maxFrameLength int) ([]byte, error) {
	header, err := prepareTCPrimaryHeader(primaryHeader, len(payload), maxFrameLength)
	if err != nil {
		return nil, err
	}
	return appendTCFECF(join(header, payload)), nil
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
