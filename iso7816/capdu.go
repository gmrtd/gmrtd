package iso7816

import (
	"fmt"
	"log/slog"

	"github.com/gmrtd/gmrtd/utils"
)

// CApdu is an ISO/IEC 7816-4 command APDU: the CLA, INS, P1 and P2 header bytes, optional
// command data and the expected response length Le.
type CApdu struct {
	cla  byte
	ins  byte
	p1   byte
	p2   byte
	data []byte // len: 0-65535
	le   int    // 0-65536
}

// String returns the C-APDU's fields in a readable form, for logging.
func (cApdu CApdu) String() string {
	return fmt.Sprintf("[CApdu] CLA:%02x, INS:%02x, P1:%02x, P2:%02x, Data:%x, LE(dec):%d", cApdu.cla, cApdu.ins, cApdu.p1, cApdu.p2, cApdu.data, cApdu.le)
}

// IsExtended reports whether the C-APDU needs extended length fields, i.e. it has more than
// 255 bytes of data or an Le above 256.
func (apdu *CApdu) IsExtended() bool {
	if (len(apdu.data) > 255) || (apdu.le > 256) {
		return true
	}

	return false
}

// NewCApdu returns a C-APDU with the given header, data and Le. Le 0 means no Le field;
// Le 256 (short) or 65536 (extended) is encoded as zero, requesting the maximum length.
func NewCApdu(cla byte, ins byte, p1 byte, p2 byte, data []byte, le int) *CApdu {
	return &CApdu{cla: cla, ins: ins, p1: p1, p2: p2, data: data, le: le}
}

// EncodeHeader returns the 4-byte command header (CLA, INS, P1, P2).
func (apdu *CApdu) EncodeHeader() []byte {
	header := make([]byte, 4)

	header[0] = apdu.cla
	header[1] = apdu.ins
	header[2] = apdu.p1
	header[3] = apdu.p2

	return header
}

// HaveLe reports whether the C-APDU has an Le field (Le > 0).
func (apdu *CApdu) HaveLe() bool {
	return apdu.le > 0
}

// EncodeLc returns the encoded Lc field: empty if there is no data, otherwise 1 byte, or 3
// bytes (a leading 0x00) for an extended C-APDU.
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
		// valid range: 1..65535
		lcBytes = append(lcBytes, 0)
		lcBytes = append(lcBytes, byte((lc/256)%0xff))
		lcBytes = append(lcBytes, byte(lc%256))
	} else {
		// Lc = 1 byte
		// valid range: 1..255
		lcBytes = append(lcBytes, byte(lc))
	}

	//slog.Debug("cApdu.EncodeLc", "lcBytes", BytesToHex(lcBytes))

	return lcBytes
}

// EncodeLe returns the encoded Le field: empty if Le is 0, otherwise 1 byte, or 2 bytes for
// an extended C-APDU. The maximum value (256 or 65536) is encoded as zero bytes.
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
		// valid range: 1..65536 (note 65536->0x0000)

		// NB bytes will correctly be x0000 if 65536!
		leBytes = append(leBytes, byte((apdu.le/256)&0xff))
		leBytes = append(leBytes, byte(apdu.le%256))
	} else {
		// Lc = 1 byte
		// valid range: 1..256 (note 256->0x00)

		// NB byte will correctly be x00 if 256!
		leBytes = append(leBytes, byte(apdu.le%256))
	}

	//slog.Debug("cApdu.EncodeLe", "leBytes", BytesToHex(leBytes))

	return leBytes
}

// HaveData reports whether the C-APDU has command data.
func (apdu *CApdu) HaveData() bool {
	return len(apdu.data) > 0
}

// Encode returns the complete encoded C-APDU: header, Lc, data and Le.
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
