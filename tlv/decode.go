package tlv

import (
	"bytes"
	"fmt"

	"github.com/gmrtd/gmrtd/utils"
)

// internal decode function - clients should use TlvDecode
func decode(data []byte) (nodes *TlvNodes, remainingData []byte, err error) {
	nodes = NewTlvNodes()

	buf := bytes.NewBuffer(data)

	for {
		if buf.Len() <= 0 {
			break
		}

		tag, length, err := ParseTagAndLength(buf)
		if err != nil {
			return nil, nil, fmt.Errorf("[decode] ParseTagAndLength error: %w", err)
		}

		// special handling for indefinite-length mode end sentinel (i.e. 0x0000)
		if tag == 0 && length == 0 {
			remainingData = bytes.Clone(buf.Bytes())
			break
		}

		if tag.IsConstructed() {
			var children *TlvNodes

			if length == -1 { // indefinite-length
				childData := bytes.Clone(buf.Bytes())
				buf = bytes.NewBuffer([]byte{})

				children, remainingData, err = decode(childData)
				if err != nil {
					return nil, nil, fmt.Errorf("[decode] error: %w", err)
				}

				node := NewTlvConstructedNode(tag)
				node.children.Nodes = append(node.children.Nodes, children.Nodes...)

				nodes.Nodes = append(nodes.Nodes, node)

				// we may or may not have remaining-data
				// if we do, then it needs to be processed as siblings for this node
				if len(remainingData) > 0 {
					buf = bytes.NewBuffer(remainingData)
					remainingData = nil
				}
			} else {
				childData, err := utils.BytesFromBuffer(buf, int(length))
				if err != nil {
					return nil, nil, fmt.Errorf("[decode] ByteBuffer error: %w", err)
				}
				children, remainingData, err = decode(childData)
				if err != nil {
					return nil, nil, fmt.Errorf("[decode] error: %w", err)
				}
				if len(remainingData) > 0 {
					return nil, remainingData, fmt.Errorf("[decode] Remaining-data not expected (%x)", remainingData)
				}
				node := NewTlvConstructedNode(tag)
				node.children.Nodes = append(node.children.Nodes, children.Nodes...)

				nodes.Nodes = append(nodes.Nodes, node)
			}
		} else {
			if length == -1 { // indefinite-length
				return nil, nil, fmt.Errorf("[decode] Indefinite-length mode is only supported for constructed tags")
			} else {
				value, err := utils.BytesFromBuffer(buf, int(length))
				if err != nil {
					return nil, nil, fmt.Errorf("[decode] ByteBuffer error: %w", err)
				}
				node := NewTlvSimpleNode(tag, value)
				nodes.AddNode(node)
			}
		}
	}

	return nodes, remainingData, nil
}

func Decode(data []byte) (nodes *TlvNodes, err error) {
	var remainingData []byte

	nodes, remainingData, err = decode(data)
	if err != nil {
		return nil, err
	}

	if len(remainingData) > 0 {
		return nil, fmt.Errorf("[Decode] Unexpected remaining-data (%x)", remainingData)
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
