package tlv

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/gmrtd/gmrtd/utils"
)

const indentStringValue = "  "

func ParseTagAndLength(buf *bytes.Buffer) (tag TlvTag, length TlvLength, err error) {
	tag, err = ParseTag(buf)
	if err != nil {
		return TlvTag(0), TlvLength(0), fmt.Errorf("[ParseTagAndLength] ParseTag error: %w", err)
	}

	length, err = ParseLength(buf)
	if err != nil {
		return TlvTag(0), TlvLength(0), fmt.Errorf("[ParseTagAndLength] ParseLength error: %w", err)
	}

	return tag, length, nil
}

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
