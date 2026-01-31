package tlv

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/gmrtd/gmrtd/utils"
)

type TlvLength int64

// decodes and returns the length
// NB returns -1 when 'indefinite-length' is indicated
func ParseLength(buf *bytes.Buffer) (length TlvLength, err error) {
	b1, err := utils.ByteFromBuffer(buf)
	if err != nil {
		return 0, fmt.Errorf("[ParseLength] ByteFromBuffer error: %w", err)
	}

	if b1 <= 0x7f {
		// 1 byte: 0xxxxxxx (7 bit length)
		length = TlvLength(b1)
	} else if b1 == 0x80 {
		// indefinite-length mode (0x80)
		// NB special-case where length is not specified and sequence is terminated by 0x0000
		//    - only valid for constructed tags
		length = -1
	} else if b1 >= 0x81 && b1 <= 0x84 {
		// 2 bytes: 10000001 xxxxxxxx (8 bit length)
		// 3 bytes: 10000010 xxxxxxxx xxxxxxxx (16 bit length)
		// 4 bytes: 10000011 xxxxxxxx xxxxxxxx xxxxxxxx (24 bit length)
		// 5 bytes: 10000100 xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx (32 bit length)
		byteLen := b1 - 0x80
		bytes, err := utils.BytesFromBuffer(buf, int(byteLen))
		if err != nil {
			return 0, fmt.Errorf("[ParseLength] ByteBuffer error: %w", err)
		}
		uint32bytes := make([]byte, 4)
		copy(uint32bytes[4-byteLen:], bytes)
		length = TlvLength(binary.BigEndian.Uint32(uint32bytes))
	} else {
		return 0, fmt.Errorf("[ParseLength] Unsupported length (b1:%02x) (remBytes:%x)", b1, buf.Bytes())
	}

	return length, nil
}

func (length TlvLength) Encode() []byte {
	out := make([]byte, 0)

	if length == -1 {
		out = append(out, byte(0x80))
	} else if length < 0 {
		// negative values other than -1 are not permitted
		panic(fmt.Sprintf("[EncodeLength] Unsupported length (%d)", length))
	} else if length <= 127 {
		out = append(out, byte(length&0xff))
	} else if length <= 0xffffffff {
		significantBytes := bytes.TrimLeft(utils.UInt64ToBytes(uint64(length)), "\x00")
		out = append(out, byte(0x80+len(significantBytes)))
		out = append(out, significantBytes...)
	} else {
		panic(fmt.Sprintf("[EncodeLength] Unsupported length (%d)", length))
	}

	return out
}
