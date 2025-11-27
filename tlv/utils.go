package tlv

import (
	"bytes"
	"fmt"
	"strings"
)

const indentString = "  "

func TagAndLength(buf *bytes.Buffer) (tag TlvTag, length TlvLength, err error) {
	tag, err = GetTag(buf)
	if err != nil {
		return TlvTag(0), TlvLength(0), fmt.Errorf("[GetTagAndLength] GetTag error: %w", err)
	}

	length, err = GetLength(buf)
	if err != nil {
		return TlvTag(0), TlvLength(0), fmt.Errorf("[GetTagAndLength] GetLength error: %w", err)
	}

	return tag, length, nil
}

func getIndentString(indent int) string {
	var sb strings.Builder
	for i := 0; i < indent; i++ {
		sb.WriteString(indentString)
	}
	return sb.String()
}
