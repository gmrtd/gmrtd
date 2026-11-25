package tlv

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/gmrtd/gmrtd/utils"
)

const indentStringValue = "  "

// ParseTagAndLength reads a tag followed by a length from r. The length is -1 for
// indefinite length.
func ParseTagAndLength(r io.Reader) (tag TlvTag, length TlvLength, err error) {
	tag, err = ParseTag(r)
	if err != nil {
		return TlvTag(0), TlvLength(0), fmt.Errorf("[ParseTagAndLength] ParseTag error: %w", err)
	}

	length, err = ParseLength(r)
	if err != nil {
		return TlvTag(0), TlvLength(0), fmt.Errorf("[ParseTagAndLength] ParseLength error: %w", err)
	}

	return tag, length, nil
}

// UnwrapTag is like Unwrap but also returns an error if the element's tag is not tag.
func UnwrapTag(tag TlvTag, data []byte) (value []byte, err error) {
	actTag, value, err := Unwrap(data)
	if err != nil {
		return nil, fmt.Errorf("[UnwrapTag] Unwrap error: %w", err)
	}

	if actTag != tag {
		return nil, fmt.Errorf("[UnwrapTag] Tag mismatch (act:%x, exp:%x)", actTag, tag)
	}

	return value, nil
}

// Unwrap parses data as exactly one TLV element and returns its tag and value without
// decoding the value. It returns an error if data is malformed, uses indefinite length,
// or has bytes after the element.
func Unwrap(data []byte) (tag TlvTag, value []byte, err error) {
	tmpBuf := bytes.NewBuffer(data)

	var length TlvLength

	tag, length, err = ParseTagAndLength(tmpBuf)
	if err != nil {
		return TlvTag(0), nil, fmt.Errorf("[Unwrap] ParseTagAndLength error: %w", err)
	}

	value, err = utils.BytesFromBuffer(tmpBuf, int(length))
	if err != nil {
		return TlvTag(0), nil, fmt.Errorf("[Unwrap] ByteBuffer error: %w", err)
	}

	// verify that we consumed all of the data
	if tmpBuf.Len() > 0 {
		return TlvTag(0), nil, fmt.Errorf("[Unwrap] Unconsumed bytes (len:%1d)", tmpBuf.Len())
	}

	return tag, value, nil
}

// DecodeEncode decodes data and re-encodes it, which normalises it to definite-length
// encoding with minimal lengths. It returns an error if data cannot be decoded.
func DecodeEncode(data []byte) ([]byte, error) {
	nodes, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("[DecodeEncode] Decode error: %w", err)
	}

	out := nodes.Encode()

	return out, nil
}

func indentString(indent int) string {
	var sb strings.Builder
	for i := 0; i < indent; i++ {
		sb.WriteString(indentStringValue)
	}
	return sb.String()
}
