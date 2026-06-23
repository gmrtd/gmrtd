package tlv

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/gmrtd/gmrtd/utils"
)

type TlvTag uint32

var errStartOfStreamEOF = errors.New("EOF at start of stream")

func ParseTag(r io.Reader) (TlvTag, error) {
	b1, err := utils.ByteFromBuffer(r)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return TlvTag(0), errStartOfStreamEOF
		}
		return TlvTag(0), fmt.Errorf("[ParseTag] ByteFromBuffer error: %w", err)
	}

	var tag TlvTag = TlvTag(b1)

	// special handling for multi-byte tags
	if (tag & 0x1f) == 0x1f {
		for {
			// prevent tags over 4 bytes
			if (tag & 0xFF000000) != 0 {
				return TlvTag(0), fmt.Errorf("[ParseTag] Tag exceeds 4 bytes (tag:%x)", tag)
			}

			tmp, err := utils.ByteFromBuffer(r)
			if err != nil {
				return TlvTag(0), fmt.Errorf("[ParseTag] ByteFromBuffer error: %w", err)
			}

			tag <<= 8
			tag += TlvTag(tmp)

			if (tmp & 0x80) == 0 {
				break
			}
		}
	}

	return tag, nil
}

func ParseTags(r io.Reader) ([]TlvTag, error) {
	var out []TlvTag

	for {
		tag, err := ParseTag(r)
		if err != nil {
			if errors.Is(err, errStartOfStreamEOF) {
				break
			}
			return nil, fmt.Errorf("[ParseTags] ParseTag error: %w", err)
		}

		out = append(out, tag)
	}

	return out, nil
}

func (tag TlvTag) Encode() []byte {
	// gracefully handle invalid tags (negative or 0)
	if tag < 1 {
		return []byte{0}
	}

	// tag >= 1, so convert to bytes and trim leading 0 bytes
	return bytes.TrimLeft(utils.UInt64ToBytes(uint64(tag)), "\x00")
}

func (tag TlvTag) IsConstructed() bool {
	var tmp uint32 = uint32(tag)

	// gracefully handle invalid tag (<1)
	if tmp < 1 {
		return false
	}

	// get the 1st byte of the tag
	for tmp > 0xFF {
		tmp >>= 8
	}

	// constructed if bit 5 is set
	return (tmp & 0x20) != 0
}
