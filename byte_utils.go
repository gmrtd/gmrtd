package gmrtd

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"os"
	"unicode"
)

func xorBytes(arr1 []byte, arr2 []byte) []byte {
	if len(arr1) != len(arr2) {
		log.Panic("Arrays must be the same length")
	}

	out := make([]byte, len(arr1))

	for i := 0; i < len(arr1); i++ {
		out[i] = arr1[i] ^ arr2[i]
	}

	return out
}

func verifyByteLength(data []byte, length int) {
	if len(data) != length {
		log.Panicf("Incorrect byte slice length (Exp:%d, Act:%d)", length, len(data))
	}
}

func HexToBytes(str string) []byte {
	out, err := hex.DecodeString(str)
	if err != nil {
		log.Panicf("Unable to convert Ascii-Hex to Bytes (Data:%s)", str)
	}
	return out
}

func BytesToHex(bytes []byte) string {
	return fmt.Sprintf("%x", bytes)
}

func PrintableBytes(data []byte) bool {
	s := string(data[:])

	for _, c := range s {
		if !unicode.IsPrint(c) {
			return false
		}
	}

	return true
}

func getBytesFromBuffer(buf *bytes.Buffer, length int) []byte {
	out := make([]byte, length)

	tmp := buf.Next(length)

	if len(tmp) != length {
		log.Panicf("[getBytesFromBuffer] Req:%d, Act:%d", length, len(tmp))
	}

	copy(out, tmp)

	return out
}

func getByteFromBuffer(buf *bytes.Buffer) byte {
	tmp := getBytesFromBuffer(buf, 1)
	return tmp[0]
}

func WriteFile(filename string, data []byte) {
	if err := os.WriteFile(filename, data, 0666); err != nil {
		log.Panic(err)
	}
}

// determines whether the data constitutes an image
// return: 'true' if image detected, otherwise 'false'
func isImage(imageBytes []byte) bool {
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

func bytesToInt(bytes []byte) int {
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
