package iso7816

import (
	"bytes"
	"slices"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/utils"
)

func TestSSCIncrement(t *testing.T) {
	testCases := []struct {
		alg    cryptoutils.BlockCipherAlg
		ksEnc  []byte
		ksMac  []byte
		ssc    []byte
		expSsc []byte
	}{
		{
			alg:    cryptoutils.TDES,
			ksEnc:  utils.HexToBytes("979ec13b1cbfe9dcd01ab0fed307eae5"),
			ksMac:  utils.HexToBytes("f1cb1f1fb5adf208806b89dc579dc1f8"),
			ssc:    utils.HexToBytes("0000000000000000"),
			expSsc: utils.HexToBytes("0000000000000001"),
		},
		{
			alg:    cryptoutils.TDES,
			ksEnc:  utils.HexToBytes("979ec13b1cbfe9dcd01ab0fed307eae5"),
			ksMac:  utils.HexToBytes("f1cb1f1fb5adf208806b89dc579dc1f8"),
			ssc:    utils.HexToBytes("0123456789abcdef"),
			expSsc: utils.HexToBytes("0123456789abcdf0"),
		},
		{
			alg:    cryptoutils.TDES,
			ksEnc:  utils.HexToBytes("979ec13b1cbfe9dcd01ab0fed307eae5"),
			ksMac:  utils.HexToBytes("f1cb1f1fb5adf208806b89dc579dc1f8"),
			ssc:    utils.HexToBytes("ffffffffffffffff"),
			expSsc: utils.HexToBytes("0000000000000000"),
		},
		{
			alg:    cryptoutils.AES,
			ksEnc:  utils.HexToBytes("f5f0e35c0d7161ee6724ee513a0d9a7f"),
			ksMac:  utils.HexToBytes("fe251c7858b356b24514b3bd5f4297d1"),
			ssc:    utils.HexToBytes("00000000000000000000000000000000"),
			expSsc: utils.HexToBytes("00000000000000000000000000000001"),
		},
		{
			alg:    cryptoutils.AES,
			ksEnc:  utils.HexToBytes("f5f0e35c0d7161ee6724ee513a0d9a7f"),
			ksMac:  utils.HexToBytes("fe251c7858b356b24514b3bd5f4297d1"),
			ssc:    utils.HexToBytes("000102030405060708090a0b0c0d0e0f"),
			expSsc: utils.HexToBytes("000102030405060708090a0b0c0d0e10"),
		},
		{
			alg:    cryptoutils.AES,
			ksEnc:  utils.HexToBytes("f5f0e35c0d7161ee6724ee513a0d9a7f"),
			ksMac:  utils.HexToBytes("fe251c7858b356b24514b3bd5f4297d1"),
			ssc:    utils.HexToBytes("ffffffffffffffffffffffffffffffff"),
			expSsc: utils.HexToBytes("00000000000000000000000000000000"),
		},
		{
			alg:    cryptoutils.AES,
			ksEnc:  utils.HexToBytes("74b94f408bbb2cd92571fd5b6370a94cce7a2fa42ae3eb4da47b97ce6eaa24c6"),
			ksMac:  utils.HexToBytes("9e28d5d9ff1d979be752e8926bf0e1d35a440fc0aefc4aa3bc5610055ac8b113"),
			ssc:    utils.HexToBytes("000102030405060708090a0b0c0d0e0f"),
			expSsc: utils.HexToBytes("000102030405060708090a0b0c0d0e10"),
		},
		{
			alg:    cryptoutils.AES,
			ksEnc:  utils.HexToBytes("74b94f408bbb2cd92571fd5b6370a94cce7a2fa42ae3eb4da47b97ce6eaa24c6"),
			ksMac:  utils.HexToBytes("9e28d5d9ff1d979be752e8926bf0e1d35a440fc0aefc4aa3bc5610055ac8b113"),
			ssc:    utils.HexToBytes("ffffffffffffffffffffffffffffffff"),
			expSsc: utils.HexToBytes("00000000000000000000000000000000"),
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

func TestSecureMessageEncode(t *testing.T) {
	testCases := []struct {
		alg         cryptoutils.BlockCipherAlg
		ksEnc       []byte
		ksMac       []byte
		ssc         []byte
		cApdu       *CApdu
		expSsc      []byte
		expEncCApdu []byte
	}{
		{
			// SELECT EF.COM (cAPDU)
			alg:         cryptoutils.TDES,
			ksEnc:       utils.HexToBytes("979EC13B1CBFE9DCD01AB0FED307EAE5"),
			ksMac:       utils.HexToBytes("F1CB1F1FB5ADF208806B89DC579DC1F8"),
			ssc:         utils.HexToBytes("887022120C06C226"),
			cApdu:       NewCApdu(0x00, 0xA4, 0x02, 0x0C, []byte{0x01, 0x1E}, 0),
			expSsc:      utils.HexToBytes("887022120C06C227"),
			expEncCApdu: utils.HexToBytes("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800"),
		},
		{
			alg:         cryptoutils.AES,
			ksEnc:       utils.HexToBytes("cc86415f2ed7e8fd663b754265695ae1"),
			ksMac:       utils.HexToBytes("581e84b8ee06c4d3eee30461498d7fb3"),
			ssc:         utils.HexToBytes("000000000000000000000000000000ba"),
			cApdu:       NewCApdu(0x00, 0x22, 0x41, 0xa4, utils.HexToBytes("800a04007f000702020302028401c3"), 0),
			expSsc:      utils.HexToBytes("000000000000000000000000000000bb"),
			expEncCApdu: utils.HexToBytes("0c2241a41d871101980953d37f67558690045d78a853b18a8e08929767a2cef172e200"),
		},
	}
	for _, tc := range testCases {
		var err error
		var sm *SecureMessaging

		sm, err = NewSecureMessaging(tc.alg, tc.ksEnc, tc.ksMac)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		sm.SetSSC(tc.ssc)

		outCApdu, err := sm.Encode(tc.cApdu)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		if !bytes.Equal(sm.ssc, tc.expSsc) {
			t.Errorf("Incorrect SSC (Exp:%x) (Act:%x)", tc.expSsc, sm.ssc)
		}

		out := outCApdu.Encode()

		if !bytes.Equal(out, tc.expEncCApdu) {
			t.Errorf("Incorrect encoded cApdu (Exp:%x) (Act:%x)", tc.expEncCApdu, out)
		}
	}
}

func TestSecureMessageDecode(t *testing.T) {
	testCases := []struct {
		alg        cryptoutils.BlockCipherAlg
		ksEnc      []byte
		ksMac      []byte
		ssc        []byte
		rApduBytes []byte
		expSsc     []byte
		expRApdu   *RApdu
	}{
		{
			// SELECT EF.COM (rAPDU)
			alg:        cryptoutils.TDES,
			ksEnc:      utils.HexToBytes("979EC13B1CBFE9DCD01AB0FED307EAE5"),
			ksMac:      utils.HexToBytes("F1CB1F1FB5ADF208806B89DC579DC1F8"),
			ssc:        utils.HexToBytes("887022120C06C227"),
			rApduBytes: utils.HexToBytes("990290008E08FA855A5D4C50A8ED9000"),
			expSsc:     utils.HexToBytes("887022120C06C228"),
			expRApdu:   NewRApdu(0x9000, utils.HexToBytes("")),
		},
		{
			alg:        cryptoutils.AES,
			ksEnc:      utils.HexToBytes("a8e85e938514ec67ae33cda3d43d3c48"),
			ksMac:      utils.HexToBytes("27f1adeb705a049a305b0c619b14b9b3"),
			ssc:        utils.HexToBytes("0000000000000000000000000000000b"),
			rApduBytes: utils.HexToBytes("8781e1012fabf9e0655d7e987fd28a8aeb19c9cadd990d49399799ed1fe465bcea56da9ba3024291d40d23d7f1e00485d71faddc6d8c1382e8028dd22efdcc72ed47663d56d20dd6c4b867956fe0507313083ae7fc54fb46133f184febbe13ad6fd3e2616a1f4a829e75ada1a0e443ca738288f6014be8a7745d8259b089e6bee35bcc4bf5b63db5fdd84244f67eca099213b70a861b4487225aa68af684278fceb4cb809de42be3ee95b0e0d72bcdb0ed47cb56efc264e04a9397a90e81ad1d81efa2d14b2ca8ec7bd997f4b1c1fd344d5dee8589c38b227ca4cb35810060a7cc76403e990290008e083eb47ef4fa82afc99000"),
			expSsc:     utils.HexToBytes("0000000000000000000000000000000c"),
			expRApdu:   NewRApdu(0x9000, utils.HexToBytes("a729901d1a71874700133107ec53306404307bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826043004a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c110461041d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c53150231008cb91e82a3")),
		},
	}
	for _, tc := range testCases {
		var err error
		var sm *SecureMessaging

		sm, err = NewSecureMessaging(tc.alg, tc.ksEnc, tc.ksMac)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		sm.SetSSC(tc.ssc)

		out, err := sm.Decode(tc.rApduBytes)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		if !bytes.Equal(sm.ssc, tc.expSsc) {
			t.Errorf("Incorrect SSC (Exp:%x) (Act:%x)", tc.expSsc, sm.ssc)
		}

		// NB we re-encode before comparing as slices.Equal doesn't play well with empty slices (i.e. rApdu without data)
		//    - not an issue as we're primarily testing the 'Secure Messaging' decode (i.e. the encryption parts)
		if !slices.Equal(out.Encode(), tc.expRApdu.Encode()) {
			t.Errorf("Incorrect rApdu (Exp:%s) (Act:%s)", tc.expRApdu, out)
		}
	}
}
