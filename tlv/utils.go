package tlv

import (
	"bytes"
	"fmt"
	"strings"
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

func indentString(indent int) string {
	var sb strings.Builder
	for i := 0; i < indent; i++ {
		sb.WriteString(indentStringValue)
	}
	return sb.String()
}
