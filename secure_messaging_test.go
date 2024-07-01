package gmrtd

import (
	"bytes"
	"testing"
)

func TestSSCIncrement(t *testing.T) {
	testCases := []struct {
		alg    BlockCipherAlg
		ksEnc  []byte
		ksMac  []byte
		ssc    []byte
		expSsc []byte
	}{
		{
			alg:    TDES,
			ksEnc:  HexToBytes("979ec13b1cbfe9dcd01ab0fed307eae5"),
			ksMac:  HexToBytes("f1cb1f1fb5adf208806b89dc579dc1f8"),
			ssc:    HexToBytes("0000000000000000"),
			expSsc: HexToBytes("0000000000000001"),
		},
		{
			alg:    TDES,
			ksEnc:  HexToBytes("979ec13b1cbfe9dcd01ab0fed307eae5"),
			ksMac:  HexToBytes("f1cb1f1fb5adf208806b89dc579dc1f8"),
			ssc:    HexToBytes("0123456789abcdef"),
			expSsc: HexToBytes("0123456789abcdf0"),
		},
		{
			alg:    TDES,
			ksEnc:  HexToBytes("979ec13b1cbfe9dcd01ab0fed307eae5"),
			ksMac:  HexToBytes("f1cb1f1fb5adf208806b89dc579dc1f8"),
			ssc:    HexToBytes("ffffffffffffffff"),
			expSsc: HexToBytes("0000000000000000"),
		},
		{
			alg:    AES,
			ksEnc:  HexToBytes("f5f0e35c0d7161ee6724ee513a0d9a7f"),
			ksMac:  HexToBytes("fe251c7858b356b24514b3bd5f4297d1"),
			ssc:    HexToBytes("00000000000000000000000000000000"),
			expSsc: HexToBytes("00000000000000000000000000000001"),
		},
		{
			alg:    AES,
			ksEnc:  HexToBytes("f5f0e35c0d7161ee6724ee513a0d9a7f"),
			ksMac:  HexToBytes("fe251c7858b356b24514b3bd5f4297d1"),
			ssc:    HexToBytes("000102030405060708090a0b0c0d0e0f"),
			expSsc: HexToBytes("000102030405060708090a0b0c0d0e10"),
		},
		{
			alg:    AES,
			ksEnc:  HexToBytes("f5f0e35c0d7161ee6724ee513a0d9a7f"),
			ksMac:  HexToBytes("fe251c7858b356b24514b3bd5f4297d1"),
			ssc:    HexToBytes("ffffffffffffffffffffffffffffffff"),
			expSsc: HexToBytes("00000000000000000000000000000000"),
		},
		{
			alg:    AES,
			ksEnc:  HexToBytes("74b94f408bbb2cd92571fd5b6370a94cce7a2fa42ae3eb4da47b97ce6eaa24c6"),
			ksMac:  HexToBytes("9e28d5d9ff1d979be752e8926bf0e1d35a440fc0aefc4aa3bc5610055ac8b113"),
			ssc:    HexToBytes("000102030405060708090a0b0c0d0e0f"),
			expSsc: HexToBytes("000102030405060708090a0b0c0d0e10"),
		},
		{
			alg:    AES,
			ksEnc:  HexToBytes("74b94f408bbb2cd92571fd5b6370a94cce7a2fa42ae3eb4da47b97ce6eaa24c6"),
			ksMac:  HexToBytes("9e28d5d9ff1d979be752e8926bf0e1d35a440fc0aefc4aa3bc5610055ac8b113"),
			ssc:    HexToBytes("ffffffffffffffffffffffffffffffff"),
			expSsc: HexToBytes("00000000000000000000000000000000"),
		},
	}
	for _, tc := range testCases {
		sm, err := NewSecureMessaging(tc.alg, tc.ksEnc, tc.ksMac)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		} else {
			sm.SetSSC(tc.ssc)
			sm.sscIncrement()

			if !bytes.Equal(sm.ssc, tc.expSsc) {
				t.Errorf("SSC mismatch (Exp:%x) (Act:%x)", tc.expSsc, sm.ssc)
			}
		}
	}
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
}

// TODO - test decode with data in response also
