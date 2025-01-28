package utils

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"unicode"
)

// isPartiallyParsed - if false then returns error if data remains after parsing
func ParseAsn1[T any](data []byte, isPartiallyParsed bool, out *T) (err error) {
	rest, err := asn1.Unmarshal(data, out)
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
		panic(fmt.Sprintf("Arrays must be the same length"))
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

func GetBytesFromBuffer(buf *bytes.Buffer, length int) []byte {
	out := make([]byte, length)

	tmp := buf.Next(length)

	if len(tmp) != length {
		panic(fmt.Sprintf("[GetBytesFromBuffer] Req:%d, Act:%d", length, len(tmp)))
	}

	copy(out, tmp)

	return out
}

func GetByteFromBuffer(buf *bytes.Buffer) byte {
	tmp := GetBytesFromBuffer(buf, 1)
	return tmp[0]
}

// determines whether the data constitutes an image
// return: 'true' if image detected, otherwise 'false'
func IsImage(imageBytes []byte) bool {
	// TODO - review following code as it seems to support more variants...
	//			https://gist.github.com/kvanh/76378993ed5de2182f762e19eccf36a0

	prefixJpeg := HexToBytes("ffd8ffe000104a464946")
	prefixJp2Bitmap := HexToBytes("0000000c6a5020200d0a")
	prefixJp2CodestreamBitmap := HexToBytes("ff4fff51")

	if !bytes.HasPrefix(imageBytes, prefixJpeg) &&
		!bytes.HasPrefix(imageBytes, prefixJp2Bitmap) &&
		!bytes.HasPrefix(imageBytes, prefixJp2CodestreamBitmap) {
		slog.Debug("Unknown image type", "prefix", imageBytes[0:10])
		return false
	}

	return true
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
