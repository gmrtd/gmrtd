package tlv

import (
	"strings"
)

const indentString = "  "

func getIndentString(indent int) string {
	var sb strings.Builder
	for i := 0; i < indent; i++ {
		sb.WriteString(indentString)
	}
	return sb.String()
}
