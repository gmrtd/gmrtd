package gmrtd

import (
	"bytes"
	"testing"
)

func TestSSCIncrement(t *testing.T) {
	// TODO
}

// TODO - add in AES tests also

func TestSecureMessageEncode(t *testing.T) {
	// SELECT EF.COM (cAPDU)
	var err error
	var sm *SecureMessaging

	sm, err = NewSecureMessaging(TDES, HexToBytes("979EC13B1CBFE9DCD01AB0FED307EAE5"), HexToBytes("F1CB1F1FB5ADF208806B89DC579DC1F8"))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	sm.SetSSC(HexToBytes("887022120C06C226"))

	capdu := NewCApdu(0x00, 0xA4, 0x02, 0x0C, []byte{0x01, 0x1E}, 0)

	exp := HexToBytes("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800")

	outCApdu, err := sm.Encode(capdu)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	out := outCApdu.Encode()

	if !bytes.Equal(sm.ssc, HexToBytes("887022120C06C227")) {
		t.Errorf("Incorrect SSC - %x", sm.ssc)
	}

	if !bytes.Equal(exp, out) {
		t.Errorf("Encode failed\nExp: %x\nAct: %x", exp, out)
	}
}

// TODO - test encode with different command.. ideally with data passed

func TestSecureMessageDecode(t *testing.T) {
	// SELECT EF.COM (rAPDU)
	var err error
	var sm *SecureMessaging

	sm, err = NewSecureMessaging(TDES, HexToBytes("979EC13B1CBFE9DCD01AB0FED307EAE5"), HexToBytes("F1CB1F1FB5ADF208806B89DC579DC1F8"))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	sm.SetSSC(HexToBytes("887022120C06C227"))

	rapduBytes := HexToBytes("990290008E08FA855A5D4C50A8ED9000")

	out, err := sm.Decode(rapduBytes)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if !bytes.Equal(sm.ssc, HexToBytes("887022120C06C228")) {
		t.Errorf("Incorrect SSC - %x", sm.ssc)
	}

	if !out.IsSuccess() || len(out.Data) != 0 {
		t.Errorf("Decode failed")
	}

	// TODO - test decode with data in response also
}
