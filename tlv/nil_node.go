package tlv

type TlvNilNode struct{}

func (node TlvNilNode) IsValidNode() bool {
	return false
}

func (node TlvNilNode) Tag() TlvTag {
	return TlvTag(-1)
}

func (node TlvNilNode) Value() []byte {
	return []byte{}
}

func (node TlvNilNode) NodeByTag(_ TlvTag) TlvNode {
	return NewTlvNilNode()
}

func (node TlvNilNode) NodeByTagOccur(_ TlvTag, _ int) TlvNode {
	return NewTlvNilNode()
}

func (node TlvNilNode) Children() []TlvNode {
	return []TlvNode{}
}

func (node TlvNilNode) Encode() []byte {
	return nil
}

func (node TlvNilNode) stringWithIndent(_ int) string {
	return ""
}

func (node TlvNilNode) String() string {
	return node.stringWithIndent(0)
}

func NewTlvNilNode() *TlvNilNode {
	return &TlvNilNode{}
}
