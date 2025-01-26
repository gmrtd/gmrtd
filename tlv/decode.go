package tlv

import (
	"bytes"
	"log"

	"github.com/gmrtd/gmrtd/utils"
)

// internal decode function - clients should use TlvDecode
func decode(data []byte) (nodes *TlvNodes, remainingData []byte) {
	nodes = NewTlvNodes()

	buf := bytes.NewBuffer(data)

	for {
		if buf.Len() <= 0 {
			break
		}

		tag := GetTag(buf)
		var length TlvLength = GetLength(buf)

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

				children, remainingData = decode(childData)

				node := NewTlvConstructedNode(tag)
				node.Children.Nodes = append(node.Children.Nodes, children.Nodes...)

				nodes.Nodes = append(nodes.Nodes, node)

				// we may or may not have remaining-data
				// if we do, then it needs to be processed as siblings for this node
				if len(remainingData) > 0 {
					buf = bytes.NewBuffer(remainingData)
					remainingData = nil
				}
			} else {
				childData := utils.GetBytesFromBuffer(buf, int(length))
				children, remainingData = decode(childData)
				if len(remainingData) > 0 {
					log.Panicf("[decode] Remaining-data not expected (%x)", remainingData)
				}
				node := NewTlvConstructedNode(tag)
				node.Children.Nodes = append(node.Children.Nodes, children.Nodes...)

				nodes.Nodes = append(nodes.Nodes, node)
			}
		} else {
			if length == -1 { // indefinite-length
				log.Panicf("[decode] Indefinite-length mode is only supported for constructed tags")
			} else {
				value := utils.GetBytesFromBuffer(buf, int(length))
				node := NewTlvSimpleNode(tag, value)
				nodes.AddNode(node)
			}
		}
	}

	return nodes, remainingData
}

func Decode(data []byte) *TlvNodes {
	nodes, remainingData := decode(data)

	if len(remainingData) > 0 {
		log.Panicf("[Decode] Unexpected remaining-data (%x)", remainingData)
	}

	return nodes
}
