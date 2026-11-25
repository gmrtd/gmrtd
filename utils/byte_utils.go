package utils

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"unicode"
)

// TrimLeadingZeroBytes returns data without its leading zero bytes, as a sub-slice of data
// (not a copy). If data is empty or all zeros, it returns an empty, non-nil slice.
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

// SafePrefix returns a slice containing at most the first prefixLength bytes
// of data.
//
// If prefixLength is greater than len(data), the entire slice is returned.
// The function never panics due to slicing beyond the bounds of the input
// slice.
//
// The returned slice references the same underlying array as data and does
// not allocate.
//
// Example:
//
//	data := []byte{1,2,3}
//	SafePrefix(data, 2) // returns []byte{1,2}
//	SafePrefix(data, 10) // returns []byte{1,2,3}
func SafePrefix(data []byte, prefixLength int) []byte {
	if prefixLength > len(data) {
		prefixLength = len(data)
	}

	return data[:prefixLength]
}

// XorBytes returns a new slice holding the byte-wise XOR of arr1 and arr2. It panics if the
// slices differ in length.
func XorBytes(arr1, arr2 []byte) []byte {
	if len(arr1) != len(arr2) {
		panic(fmt.Sprintf("Arrays must be the same length (arr1:%1d, arr2:%1d)", len(arr1), len(arr2)))
	}

	out := make([]byte, len(arr1))

	for i := 0; i < len(arr1); i++ {
		out[i] = arr1[i] ^ arr2[i]
	}

	return out
}

// HexToBytes decodes the hex string str (upper or lower case, no separators). It panics if
// str is not valid hex, so it is intended for constants and tests, not untrusted input.
func HexToBytes(str string) []byte {
	out, err := hex.DecodeString(str)
	if err != nil {
		panic(fmt.Sprintf("Unable to convert Ascii-Hex to Bytes (Data:%s)", str))
	}
	return out
}

// BytesToHex returns bytes encoded as lower-case hex with no separators.
func BytesToHex(bytes []byte) string {
	return fmt.Sprintf("%x", bytes)
}

// PrintableBytes reports whether every byte of data, taken as a Latin-1 code point, is
// printable according to unicode.IsPrint. It returns true for empty data.
func PrintableBytes(data []byte) bool {
	for _, b := range data {
		if !unicode.IsPrint(rune(b)) {
			return false
		}
	}

	return true
}

// BytesFromBuffer reads exactly length bytes from r into a new slice. It returns an error if
// length is negative or fewer bytes are available (wrapping io.EOF or io.ErrUnexpectedEOF).
func BytesFromBuffer(r io.Reader, length int) ([]byte, error) {
	if length < 0 {
		return nil, fmt.Errorf("[BytesFromBuffer] invalid length (%d)", length)
	}

	// bound the allocation to the reader's actually-available bytes, where known, so a
	// hostile length field (e.g. a crafted TLV length) can't force a huge upfront
	// allocation for a request that could never be satisfied anyway. Mirrors io.ReadFull's
	// own EOF/ErrUnexpectedEOF convention so callers that distinguish the two (e.g. to
	// detect a clean end-of-stream) keep working via errors.Is.
	if b, ok := r.(interface{ Len() int }); ok {
		if avail := b.Len(); length > avail {
			if avail == 0 {
				return nil, fmt.Errorf("[BytesFromBuffer] Req:%d, Act:%d: %w", length, avail, io.EOF)
			}
			return nil, fmt.Errorf("[BytesFromBuffer] Req:%d, Act:%d: %w", length, avail, io.ErrUnexpectedEOF)
		}
	}

	tmp := make([]byte, length)

	n, err := io.ReadFull(r, tmp)
	if err != nil {
		return nil, fmt.Errorf("[BytesFromBuffer] Req:%d, Act:%d: %w", length, n, err)
	}

	return tmp, nil
}

// ByteFromBuffer reads a single byte from r, returning an error if none is available.
func ByteFromBuffer(r io.Reader) (byte, error) {
	tmp, err := BytesFromBuffer(r, 1)
	if err != nil {
		return 0, fmt.Errorf("[ByteFromBuffer] GetBytesFromBuffer error: %w", err)
	}

	return tmp[0], err
}

// BytesToInt interprets bytes as an unsigned big-endian integer; empty input gives 0. Inputs
// longer than the size of int overflow silently, so callers must bound the length.
func BytesToInt(bytes []byte) int {
	var out int

	for i := 0; i < len(bytes); i++ {
		out <<= 8
		out += int(bytes[i])
	}

	return out
}

// UInt16ToBytes returns value as 2 big-endian bytes.
func UInt16ToBytes(value uint16) []byte {
	var out []byte = make([]byte, 2)
	binary.BigEndian.PutUint16(out, value)
	return out
}

// UInt32ToBytes returns value as 4 big-endian bytes.
func UInt32ToBytes(value uint32) []byte {
	var out []byte = make([]byte, 4)
	binary.BigEndian.PutUint32(out, value)
	return out
}

// UInt64ToBytes returns value as 8 big-endian bytes.
func UInt64ToBytes(value uint64) []byte {
	var out []byte = make([]byte, 8)
	binary.BigEndian.PutUint64(out, value)
	return out
}
