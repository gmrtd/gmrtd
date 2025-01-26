package tlv

type TlvNode interface {
	IsValidNode() bool
	GetTag() TlvTag
	GetValue() []byte
	GetNode(tag TlvTag) TlvNode
	GetNodeByOccur(tag TlvTag, occurrence int) TlvNode
	Encode() []byte
	String() string
	stringWithIndent(indent int) string
}
