package utils

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"unicode"
)

func TrimLeadingZeroBytes(data []byte) []byte {
	for i, b := range data {
		if b != 0 {
			return data[i:]
		}
	}

	// if all bytes are zero, then return empty slice
	return []byte{}
}

// isPartiallyParsed - if false then returns error if data remains after parsing
func ParseAsn1Ex[T any](data []byte, out *T) (remainingData []byte, err error) {
	remainingData, err = asn1.Unmarshal(data, out)
	if err != nil {
		return nil, fmt.Errorf("(ParseAsn1Ex) error: %w", err)
	}

	return remainingData, nil
}

// isPartiallyParsed - if false then returns error if data remains after parsing
func ParseAsn1[T any](data []byte, isPartiallyParsed bool, out *T) (err error) {
	var rest []byte

	rest, err = ParseAsn1Ex(data, out)
	if err != nil {
		return fmt.Errorf("(ParseAsn1) error: %w", err)
	}

	if !isPartiallyParsed && (len(rest) > 0) {
		return fmt.Errorf("unexpected data remaining after ASN1 parsing (Data:%x) (Remaining:%x)", data, rest)
	}

	return nil
}

func XorBytes(arr1 []byte, arr2 []byte) []byte {
	if len(arr1) != len(arr2) {
		panic(fmt.Sprintf("Arrays must be the same length (arr1:%1d, arr2:%1d)", len(arr1), len(arr2)))
	}

	out := make([]byte, len(arr1))

	for i := 0; i < len(arr1); i++ {
		out[i] = arr1[i] ^ arr2[i]
	}

	return out
}

func VerifyByteLength(data []byte, length int) {
	if len(data) != length {
		panic(fmt.Sprintf("Incorrect byte slice length (Exp:%d, Act:%d)", length, len(data)))
	}
}

func HexToBytes(str string) []byte {
	out, err := hex.DecodeString(str)
	if err != nil {
		panic(fmt.Sprintf("Unable to convert Ascii-Hex to Bytes (Data:%s)", str))
	}
	return out
}

func BytesToHex(bytes []byte) string {
	return fmt.Sprintf("%x", bytes)
}

func PrintableBytes(data []byte) bool {
	for _, byte := range data {
		if !unicode.IsPrint(rune(byte)) {
			return false
		}
	}

	return true
}

func GetBytesFromBuffer(buf *bytes.Buffer, length int) ([]byte, error) {
	tmp := buf.Next(length)

	if len(tmp) != length {
		return nil, fmt.Errorf("[GetBytesFromBuffer] Req:%d, Act:%d", length, len(tmp))
	}

	return bytes.Clone(tmp), nil
}

func GetByteFromBuffer(buf *bytes.Buffer) (byte, error) {
	tmp, err := GetBytesFromBuffer(buf, 1)
	return tmp[0], err
}

func BytesToInt(bytes []byte) int {
	var out int

	for i := 0; i < len(bytes); i++ {
		out <<= 8
		out += int(bytes[i])
	}

	return out
}

func UInt16ToBytes(value uint16) []byte {
	var out []byte = make([]byte, 2)
	binary.BigEndian.PutUint16(out, value)
	return out
}

func UInt32ToBytes(value uint32) []byte {
	var out []byte = make([]byte, 4)
	binary.BigEndian.PutUint32(out, value)
	return out
}

func UInt64ToBytes(value uint64) []byte {
	var out []byte = make([]byte, 8)
	binary.BigEndian.PutUint64(out, value)
	return out
}
