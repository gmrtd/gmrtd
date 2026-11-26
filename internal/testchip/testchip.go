// Package testchip provides simulated eMRTD chips for tests: Files serves EFs in plain, and
// BACChip completes BAC and then wraps an inner chip in 3DES secure messaging. It is internal
// and only imported by test files.
package testchip

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/tlv"
	"github.com/gmrtd/gmrtd/utils"
)

// BACChip is a test chip that completes BAC (9303p11 4.3) for one MRZ and then answers every command
// under 3DES secure messaging, passing the unwrapped command to an inner chip that answers in plain.
// A command that is not SM-wrapped, or whose MAC does not verify, is refused with 6988 once BAC has
// completed, so a read that goes through this chip end to end proves it ran under secure messaging.
type BACChip struct {
	t     testing.TB
	inner iso7816.Transceiver

	kEnc, kMac []byte // BAC keys derived from the MRZ
	rndIc      []byte
	kIc        []byte

	ksEnc, ksMac []byte // session keys, set once EXTERNAL AUTHENTICATE succeeds
	ssc          []byte
}

var _ iso7816.Transceiver = (*BACChip)(nil)

func NewBAC(t testing.TB, pass *password.Password, inner iso7816.Transceiver) *BACChip {
	t.Helper()

	key, err := pass.Key()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	seed := key[0:16]

	return &BACChip{
		t:     t,
		inner: inner,
		kEnc:  cryptoutils.KDF(seed, cryptoutils.KDF_COUNTER_KSENC, cryptoutils.TDES, 112),
		kMac:  cryptoutils.KDF(seed, cryptoutils.KDF_COUNTER_KSMAC, cryptoutils.TDES, 112),
		rndIc: utils.HexToBytes("4608F91988702212"),
		kIc:   utils.HexToBytes("0B4F80323EB3191CB04970CB4052790B"),
	}
}

func (chip *BACChip) Transceive(cla int, ins int, p1 int, p2 int, data []byte, le int, encodedData []byte) []byte {
	if chip.ksEnc == nil {
		switch ins {
		case int(iso7816.INS_GET_CHALLENGE):
			return append(bytes.Clone(chip.rndIc), 0x90, 0x00)
		case int(iso7816.INS_EXTERNAL_AUTHENTICATE):
			return chip.externalAuthenticate(data)
		}
		return chip.inner.Transceive(cla, ins, p1, p2, data, le, encodedData)
	}

	return chip.smTransceive(cla, ins, p1, p2, data)
}

func (chip *BACChip) tdes(key, data []byte, encrypt bool) []byte {
	block, err := cryptoutils.CipherForKey(cryptoutils.TDES, key)
	if err != nil {
		chip.t.Errorf("test chip: CipherForKey error: %s", err)
		return nil
	}
	out, err := cryptoutils.CryptCBC(block, make([]byte, cryptoutils.DES_BLOCK_SIZE_BYTES), data, encrypt)
	if err != nil {
		chip.t.Errorf("test chip: CryptCBC error: %s", err)
		return nil
	}
	return out
}

func (chip *BACChip) mac(key, data []byte) []byte {
	out, err := cryptoutils.ISO9797RetailMacDes(key, cryptoutils.ISO9797Method2Pad(data, cryptoutils.DES_BLOCK_SIZE_BYTES))
	if err != nil {
		chip.t.Errorf("test chip: ISO9797RetailMacDes error: %s", err)
		return nil
	}
	return out
}

func (chip *BACChip) externalAuthenticate(data []byte) []byte {
	if len(data) != 40 {
		return utils.HexToBytes("6700")
	}

	eIfd, mIfd := data[0:32], data[32:40]
	if !bytes.Equal(chip.mac(chip.kMac, eIfd), mIfd) {
		return utils.HexToBytes("6300")
	}

	s := chip.tdes(chip.kEnc, eIfd, false)
	if len(s) != 32 || !bytes.Equal(s[8:16], chip.rndIc) {
		return utils.HexToBytes("6300")
	}
	rndIfd, kIfd := s[0:8], s[16:32]

	r := make([]byte, 0, 32)
	r = append(r, chip.rndIc...)
	r = append(r, rndIfd...)
	r = append(r, chip.kIc...)
	eIc := chip.tdes(chip.kEnc, r, true)
	mIc := chip.mac(chip.kMac, eIc)

	seed := utils.XorBytes(kIfd, chip.kIc)
	chip.ksEnc = cryptoutils.KDF(seed, cryptoutils.KDF_COUNTER_KSENC, cryptoutils.TDES, 112)
	chip.ksMac = cryptoutils.KDF(seed, cryptoutils.KDF_COUNTER_KSMAC, cryptoutils.TDES, 112)
	chip.ssc = append(bytes.Clone(chip.rndIc[4:8]), rndIfd[4:8]...)

	out := append(eIc, mIc...)
	return append(out, 0x90, 0x00)
}

func (chip *BACChip) sscIncrement() {
	for i := len(chip.ssc) - 1; i >= 0; i-- {
		chip.ssc[i]++
		if chip.ssc[i] != 0 {
			return
		}
	}
}

func (chip *BACChip) smTransceive(cla int, ins int, p1 int, p2 int, data []byte) []byte {
	const rApduSmDataObjectsMissing = "6988"

	if cla&0x0C != 0x0C {
		return utils.HexToBytes(rApduSmDataObjectsMissing)
	}

	nodes, err := tlv.Decode(data)
	if err != nil {
		return utils.HexToBytes(rApduSmDataObjectsMissing)
	}

	do87 := nodes.NodeByTag(0x87)
	do97 := nodes.NodeByTag(0x97)
	do8E := nodes.NodeByTag(0x8E)
	if !do8E.IsValidNode() {
		return utils.HexToBytes(rApduSmDataObjectsMissing)
	}

	// command MAC: SSC || padded header || DO87 || DO97
	chip.sscIncrement()
	macData := bytes.Clone(chip.ssc)
	macData = append(macData, cryptoutils.ISO9797Method2Pad([]byte{byte(cla), byte(ins), byte(p1), byte(p2)}, cryptoutils.DES_BLOCK_SIZE_BYTES)...)
	macData = append(macData, do87.Encode()...)
	macData = append(macData, do97.Encode()...)
	if !bytes.Equal(chip.mac(chip.ksMac, macData), do8E.Value()) {
		return utils.HexToBytes(rApduSmDataObjectsMissing)
	}

	var plain []byte
	if do87.IsValidNode() {
		value := do87.Value()
		if len(value) < 1 || value[0] != 0x01 {
			return utils.HexToBytes(rApduSmDataObjectsMissing)
		}
		if plain, err = cryptoutils.ISO9797Method2Unpad(chip.tdes(chip.ksEnc, value[1:], false)); err != nil {
			return utils.HexToBytes(rApduSmDataObjectsMissing)
		}
	}

	le := 0
	if do97.IsValidNode() {
		for _, b := range do97.Value() {
			le = (le << 8) | int(b)
		}
		if le == 0 {
			le = 256
			if len(do97.Value()) > 1 {
				le = 65536
			}
		}
	}

	rsp := chip.inner.Transceive(cla&^0x0C, ins, p1, p2, plain, le, nil)
	if len(rsp) < 2 {
		return []byte{0x6F, 0x00}
	}
	rData, sw := rsp[:len(rsp)-2], rsp[len(rsp)-2:]

	// response: [DO87] DO99 DO8E, MAC over SSC || DO87 || DO99
	chip.sscIncrement()
	out := &tlv.TlvNodes{}
	if len(rData) > 0 {
		encrypted := chip.tdes(chip.ksEnc, cryptoutils.ISO9797Method2Pad(rData, cryptoutils.DES_BLOCK_SIZE_BYTES), true)
		out.AddNode(tlv.NewTlvSimpleNode(tlv.TlvTag(0x87), append([]byte{0x01}, encrypted...)))
	}
	out.AddNode(tlv.NewTlvSimpleNode(tlv.TlvTag(0x99), bytes.Clone(sw)))
	out.AddNode(tlv.NewTlvSimpleNode(tlv.TlvTag(0x8E), chip.mac(chip.ksMac, append(bytes.Clone(chip.ssc), out.Encode()...))))

	return append(out.Encode(), sw...)
}

// Files is a plain chip that serves a set of EFs by file id: SELECT succeeds for the MF,
// the MRTD AID and those files, READ BINARY returns slices of the selected file, and anything else
// (e.g. BAC or PACE) is answered as unsupported. Enough for a read to run all of its steps without
// a card.
type Files struct {
	ByID     map[uint16][]byte // file contents by file identifier
	selected []byte
}

// Selected returns the contents of the currently selected EF, or nil if none is selected.
func (transceiver *Files) Selected() []byte { return transceiver.selected }

var _ iso7816.Transceiver = (*Files)(nil)

func (transceiver *Files) Transceive(_ int, ins int, p1 int, p2 int, data []byte, le int, _ []byte) []byte {
	switch {
	case ins == int(iso7816.INS_SELECT) && p1 == 0x02: // select EF
		transceiver.selected = nil
		if len(data) != 2 {
			return utils.HexToBytes("6A82")
		}
		fileData, ok := transceiver.ByID[binary.BigEndian.Uint16(data)]
		if !ok {
			return utils.HexToBytes("6A82")
		}
		transceiver.selected = fileData
		return utils.HexToBytes("9000")

	case ins == int(iso7816.INS_SELECT): // select MF / AID
		return utils.HexToBytes("9000")

	case ins == int(iso7816.INS_READ_BINARY):
		if transceiver.selected == nil {
			return utils.HexToBytes("6A82")
		}
		offset := (p1 * 256) + p2
		if offset > len(transceiver.selected) {
			return utils.HexToBytes("6B00")
		}
		end := min(offset+le, len(transceiver.selected))
		return append(bytes.Clone(transceiver.selected[offset:end]), 0x90, 0x00)
	}

	return utils.HexToBytes("6D00")
}
