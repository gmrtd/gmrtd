package iso7816

import (
	"fmt"
	"log"
	"log/slog"

	"github.com/gmrtd/gmrtd/utils"
)

type CApdu struct {
	cla  byte
	ins  byte
	p1   byte
	p2   byte
	data []byte // len: 0-65535
	le   int    // 0-65536
}

func (cApdu CApdu) String() string {
	return fmt.Sprintf("[CApdu] CLA:%02x, INS:%02x, P1:%02x, P2:%02x, Data:%x, LE(dec):%d", cApdu.cla, cApdu.ins, cApdu.p1, cApdu.p2, cApdu.data, cApdu.le)
}

func (apdu *CApdu) IsExtended() bool {
	if (len(apdu.data) > 255) || (apdu.le > 256) {
		return true
	}

	return false
}

func NewCApdu(cla byte, ins byte, p1 byte, p2 byte, data []byte, le int) *CApdu {
	return &CApdu{cla: cla, ins: ins, p1: p1, p2: p2, data: data, le: le}
}

func (apdu *CApdu) EncodeHeader() []byte {
	header := make([]byte, 4)

	header[0] = apdu.cla
	header[1] = apdu.ins
	header[2] = apdu.p1
	header[3] = apdu.p2

	return header
}

func (apdu *CApdu) HaveLe() bool {
	return apdu.le > 0
}

func (apdu *CApdu) EncodeLc() []byte {
	var lcBytes []byte
	var lc int = len(apdu.data)

	// Lc: 0,1,3 bytes
	//
	// Encodes the number (Nc) of bytes of command data to follow
	// 0 bytes denotes Nc=0
	// 1 byte with a value from 1 to 255 denotes Nc with the same length
	// 3 bytes, the first of which must be 0, denotes Nc in the range 1 to 65 535 (all three bytes may not be zero)

	//slog.Debug("cApdu.EncodeLc", "lc", lc)

	if lc <= 0 {
		// Lc = 0 bytes
		return lcBytes
	}

	if apdu.IsExtended() {
		// Lc = 3 bytes

		if lc < 1 || lc > 65535 {
			log.Panicf("LC must be between 1 and 65535 (act:%d)", lc)
		}

		lcBytes = append(lcBytes, 0)
		lcBytes = append(lcBytes, byte((lc/256)%0xff))
		lcBytes = append(lcBytes, byte(lc%256))
	} else {
		// Lc = 1 byte

		if lc < 1 || lc > 255 {
			log.Panicf("LC must be between 1 and 255 (act:%d)", lc)
		}

		lcBytes = append(lcBytes, byte(lc))
	}

	//slog.Debug("cApdu.EncodeLc", "lcBytes", BytesToHex(lcBytes))

	return lcBytes
}

func (apdu *CApdu) EncodeLe() []byte {
	var leBytes []byte

	// Le: 0,1,2,3 bytes
	//
	// Encodes the maximum number (Ne) of response bytes expected
	// 0 bytes denotes Ne=0
	// 1 byte in the range 1 to 255 denotes that value of Ne, or 0 denotes Ne=256
	// 2 bytes (if extended Lc was present in the command) in the range 1 to 65 535 denotes Ne of that value, or two zero bytes denotes 65 536
	// 3 bytes (if Lc was not present in the command), the first of which must be 0, denote Ne in the same way as two-byte Le

	//slog.Debug("cApdu.EncodeLe", "le", apdu.le)

	if apdu.le <= 0 {
		// Lc = 0 bytes
		return leBytes
	}

	if apdu.IsExtended() {
		// Lc = 2 or 3 bytes

		// NB range is 1..65,635 (NOT 65,535!)
		if apdu.le < 1 || apdu.le > 65536 {
			log.Panicf("LE must be between 1 and 65536 (act:%d)", apdu.le)
		}

		// NB bytes will correctly be x0000 if 65536!
		leBytes = append(leBytes, byte((apdu.le/256)&0xff))
		leBytes = append(leBytes, byte(apdu.le%256))
	} else {
		// Lc = 1 byte

		// NB range is 1..256 (not 255!)
		if apdu.le < 1 || apdu.le > 256 {
			log.Panicf("LE must be between 1 and 256 (act:%d)", apdu.le)
		}

		// NB byte will correctly be x00 if 256!
		leBytes = append(leBytes, byte(apdu.le%256))
	}

	//slog.Debug("cApdu.EncodeLe", "leBytes", BytesToHex(leBytes))

	return leBytes
}

func (apdu *CApdu) HaveData() bool {
	return len(apdu.data) > 0
}

func (apdu *CApdu) Encode() []byte {
	out := apdu.EncodeHeader()
	out = append(out, apdu.EncodeLc()...)
	if len(apdu.data) > 0 {
		out = append(out, apdu.data...)
	}
	out = append(out, apdu.EncodeLe()...)

	slog.Debug("cApdu.Encode", "cApdu", apdu.String(), "cApdu-bytes", utils.BytesToHex(out))

	return out
}
