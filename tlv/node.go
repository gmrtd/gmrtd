package tlv

type TlvNode interface {
	IsValidNode() bool
	Tag() TlvTag
	Value() []byte
	NodeByTag(tag TlvTag) TlvNode
	NodeByTagOccur(tag TlvTag, occurrence int) TlvNode
	Encode() []byte
	String() string
	stringWithIndent(indent int) string
}
