package tlv

import (
	"bytes"
	"fmt"

	"github.com/gmrtd/gmrtd/utils"
)

type TlvTag int

func GetTag(buf *bytes.Buffer) (TlvTag, error) {
	b1, err := utils.GetByteFromBuffer(buf)
	if err != nil {
		return TlvTag(0), fmt.Errorf("[GetTag] GetByteFromBuffer error: %w", err)
	}

	var tag int = int(b1)

	// special handling for multi-byte tags
	if (tag & 0x1f) == 0x1f {
		for {
			tmp, err := utils.GetByteFromBuffer(buf)
			if err != nil {
				return TlvTag(0), fmt.Errorf("[GetTag] GetByteFromBuffer error: %w", err)
			}

			tag <<= 8
			tag += int(tmp)

			if (tmp & 0x80) == 0 {
				break
			}
		}
	}

	return TlvTag(tag), nil
}

func GetTags(buf *bytes.Buffer) ([]TlvTag, error) {
	var out []TlvTag

	for {
		if buf.Len() <= 0 {
			break
		}

		tag, err := GetTag(buf)
		if err != nil {
			return nil, fmt.Errorf("[GetTags] GetTag error: %w", err)
		}

		out = append(out, tag)
	}

	return out, nil
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
