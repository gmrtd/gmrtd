package testchip

import (
	"bytes"
	"testing"

	"github.com/gmrtd/gmrtd/bac"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/utils"
)

// The reader tests rely on BACChip refusing anything that is not correctly protected once BAC
// has completed: that is what makes a successful read through it prove secure messaging was used.
func TestBACChipRefusesUnprotectedCommands(t *testing.T) {
	pass, err := password.NewPasswordMrzi("123456", "100101", "301225")
	if err != nil {
		t.Fatal(err)
	}
	file := utils.HexToBytes("5302ABCD")
	chip := NewBAC(t, pass, &Files{ByID: map[uint16][]byte{0x0101: file}})
	nfc := iso7816.NewNfcSession(chip)
	if _, err := bac.NewBAC(nfc, &document.Document{}, pass).DoBAC(); err != nil {
		t.Fatal(err)
	}

	got, err := nfc.ReadFile(0x0101)
	if err != nil || !bytes.Equal(got, file) {
		t.Fatalf("protected read = %x, %v; want %x", got, err, file)
	}

	t.Run("plain command", func(t *testing.T) {
		if rsp := chip.Transceive(0x00, int(iso7816.INS_SELECT), 0x02, 0x0C, []byte{0x01, 0x01}, 0, nil); !bytes.Equal(rsp, utils.HexToBytes("6988")) {
			t.Errorf("plain SELECT after BAC = %x, want 6988", rsp)
		}
	})

	t.Run("bad MAC", func(t *testing.T) {
		protected, err := nfc.SM().Encode(iso7816.NewCApdu(0x00, iso7816.INS_SELECT, 0x02, 0x0C, []byte{0x01, 0x01}, 0))
		if err != nil {
			t.Fatal(err)
		}
		encoded := protected.Encode()
		data := bytes.Clone(encoded[5 : 5+int(encoded[4])])
		data[len(data)-1] ^= 1 // last byte of DO8E
		if rsp := chip.Transceive(int(encoded[0]), int(encoded[1]), int(encoded[2]), int(encoded[3]), data, 0, nil); !bytes.Equal(rsp, utils.HexToBytes("6988")) {
			t.Errorf("SELECT with a bad MAC = %x, want 6988", rsp)
		}
	})
}

func TestFilesErrors(t *testing.T) {
	files := &Files{ByID: map[uint16][]byte{0x0101: utils.HexToBytes("5302ABCD")}}
	for _, tc := range []struct {
		name            string
		ins, p1, p2, le int
		data            []byte
		want            string
	}{
		{"read with nothing selected", int(iso7816.INS_READ_BINARY), 0, 0, 4, nil, "6A82"},
		{"select unknown file", int(iso7816.INS_SELECT), 0x02, 0x0C, 0, []byte{0x01, 0x02}, "6A82"},
		{"select malformed file id", int(iso7816.INS_SELECT), 0x02, 0x0C, 0, []byte{0x01}, "6A82"},
		{"unsupported instruction", int(iso7816.INS_GET_CHALLENGE), 0, 0, 8, nil, "6D00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rsp := files.Transceive(0, tc.ins, tc.p1, tc.p2, tc.data, tc.le, nil); !bytes.Equal(rsp, utils.HexToBytes(tc.want)) {
				t.Errorf("response = %x, want %s", rsp, tc.want)
			}
		})
	}

	files.Transceive(0, int(iso7816.INS_SELECT), 0x02, 0x0C, []byte{0x01, 0x01}, 0, nil)
	if !bytes.Equal(files.Selected(), files.ByID[0x0101]) {
		t.Fatal("expected the file to be selected")
	}
	if rsp := files.Transceive(0, int(iso7816.INS_READ_BINARY), 0, 5, nil, 4, nil); !bytes.Equal(rsp, utils.HexToBytes("6B00")) {
		t.Errorf("read past the end = %x, want 6B00", rsp)
	}
}
