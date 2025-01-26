package tlv

type TlvNilNode struct{}

func (node TlvNilNode) IsValidNode() bool {
	return false
}

func (node TlvNilNode) GetTag() TlvTag {
	return TlvTag(-1)
}

func (node TlvNilNode) GetValue() []byte {
	return nil
}

func (node TlvNilNode) GetNode(tag TlvTag) TlvNode {
	return NewTlvNilNode()
}

func (node TlvNilNode) GetNodeByOccur(tag TlvTag, occurrence int) TlvNode {
	return NewTlvNilNode()
}

func (node TlvNilNode) Encode() []byte {
	return nil
}

func (node TlvNilNode) stringWithIndent(indent int) string {
	return ""
}

func (node TlvNilNode) String() string {
	return node.stringWithIndent(0)
}

func NewTlvNilNode() *TlvNilNode {
	return &TlvNilNode{}
}
