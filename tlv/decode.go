package tlv

import (
	"bytes"
	"fmt"

	"github.com/gmrtd/gmrtd/utils"
)

const (
	maxDecodeDepth = 50
	maxDecodeNodes = 10000
)

func decodeFromBuffer(buf *bytes.Buffer, depth int, nodeCount *int) (nodes *TlvNodes, err error) {
	if depth > maxDecodeDepth {
		return nil, fmt.Errorf("[decode] exceeded maximum nesting depth (%d)", maxDecodeDepth)
	}

	nodes = &TlvNodes{}

	for buf.Len() > 0 {
		tag, length, err := ParseTagAndLength(buf)
		if err != nil {
			return nil, fmt.Errorf("[decode] ParseTagAndLength error: %w", err)
		}

		if tag == 0 && length == 0 {
			return nodes, nil
		}

		*nodeCount++
		if *nodeCount > maxDecodeNodes {
			return nil, fmt.Errorf("[decode] exceeded maximum node count (%d)", maxDecodeNodes)
		}

		if tag.IsConstructed() {
			var children *TlvNodes

			if length == -1 {
				children, err = decodeFromBuffer(buf, depth+1, nodeCount)
				if err != nil {
					return nil, fmt.Errorf("[decode] error: %w", err)
				}
			} else {
				childData, err := utils.BytesFromBuffer(buf, int(length))
				if err != nil {
					return nil, fmt.Errorf("[decode] ByteBuffer error: %w", err)
				}
				childBuf := bytes.NewBuffer(childData)
				children, err = decodeFromBuffer(childBuf, depth+1, nodeCount)
				if err != nil {
					return nil, fmt.Errorf("[decode] error: %w", err)
				}
				if childBuf.Len() > 0 {
					return nil, fmt.Errorf("[decode] Remaining-data not expected (%x)", childBuf.Bytes())
				}
			}

			node := NewTlvConstructedNode(tag)
			node.children.AddNodes(*children)
			nodes.AddNode(node)
		} else {
			if length == -1 {
				return nil, fmt.Errorf("[decode] Indefinite-length mode is only supported for constructed tags")
			}
			value, err := utils.BytesFromBuffer(buf, int(length))
			if err != nil {
				return nil, fmt.Errorf("[decode] ByteBuffer error: %w", err)
			}
			nodes.AddNode(NewTlvSimpleNode(tag, value))
		}
	}

	return nodes, nil
}

func Decode(data []byte) (nodes *TlvNodes, err error) {
	nodeCount := 0
	buf := bytes.NewBuffer(data)

	nodes, err = decodeFromBuffer(buf, 0, &nodeCount)
	if err != nil {
		return nil, err
	}

	if buf.Len() > 0 {
		return nil, fmt.Errorf("[Decode] Unexpected remaining-data (%x)", buf.Bytes())
	}

	return nodes, nil
}

func MustDecode(data []byte) (nodes *TlvNodes) {
	var err error

	nodes, err = Decode(data)
	if err != nil {
		panic(fmt.Sprintf("[MustDecode] Decode error: %s", err))
	}

	return nodes
}
