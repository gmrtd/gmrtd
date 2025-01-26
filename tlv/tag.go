package tlv

import (
	"bytes"

	"github.com/gmrtd/gmrtd/utils"
)

type TlvTag int

func GetTag(buf *bytes.Buffer) TlvTag {
	b1 := utils.GetByteFromBuffer(buf)

	var tag int = int(b1)

	// special handling for multi-byte tags
	if (tag & 0x1f) == 0x1f {
		for {
			tmp := utils.GetByteFromBuffer(buf)

			tag <<= 8
			tag += int(tmp)

			if (tmp & 0x80) == 0 {
				break
			}
		}
	}

	return TlvTag(tag)
}

func GetTags(buf *bytes.Buffer) []TlvTag {
	var out []TlvTag

	for {
		if buf.Len() <= 0 {
			break
		}
		out = append(out, GetTag(buf))
	}

	return out
}

func (tag TlvTag) Encode() []byte {
	return bytes.TrimLeft(utils.UInt64ToBytes(uint64(tag)), "\x00")
}

func (tag TlvTag) IsConstructed() bool {
	var tmp int = int(tag)

	// get the 1st byte of the tag
	for {
		if tmp <= 0xFF {
			break
		}
		tmp >>= 8
	}

	// constructed if bit 5 is set
	return (tmp & 0x20) == 0x20
}
