package gmrtd

import (
	"bytes"
	"testing"
)

func TestSelectAidMrtd(t *testing.T) {
	var nfc *NfcSession

	{
		var transceiver *MockTransceiver = new(MockTransceiver)

		// add in expected request/response tuples
		transceiver.AddReqRsp("00A4040C07A0000002471001", "9000")

		nfc = NewNfcSession(transceiver)
	}

	selected, err := nfc.SelectAid([]byte(HexToBytes(MRTD_AID)))

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if !selected {
		t.Errorf("Unable to SELECT AID")
	}
}

func TestNfcSessionSecureMessagingTDES(t *testing.T) {
	// Worked example from 9303p11 D.4 SECURE MESSAGING

	expEfComData := HexToBytes("60145F0104303130365F36063034303030305C026175")

	var nfc *NfcSession

	{
		var transceiver *MockTransceiver = new(MockTransceiver)

		// add in expected request/response tuples
		transceiver.AddReqRsp("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800", "990290008E08FA855A5D4C50A8ED9000")
		transceiver.AddReqRsp("0CB000000D9701048E08ED6705417E96BA5500", "8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000")
		transceiver.AddReqRsp("0CB000040D9701128E082EA28A70F3C7B53500", "871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D749000")

		nfc = NewNfcSession(transceiver)
	}

	var err error

	nfc.sm, err = NewSecureMessaging(TDES, HexToBytes("979EC13B1CBFE9DCD01AB0FED307EAE5"), HexToBytes("F1CB1F1FB5ADF208806B89DC579DC1F8"))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	nfc.sm.SetSSC(HexToBytes("887022120C06C226"))

	// Read EF.COM
	actEfComData := nfc.ReadFile(MRTDFileIdEFCOM)

	if !bytes.Equal(actEfComData, expEfComData) {
		t.Errorf("Incorrect EF.COM data (Exp:%x, Act:%x)", expEfComData, actEfComData)
	}

	if !bytes.Equal(nfc.sm.ssc, HexToBytes("887022120C06C22C")) {
		t.Errorf("Incorrect SSC")
	}
}

func TestNfcSessionSecureMessagingAES(t *testing.T) {
	expEfComData := HexToBytes("60185F0104303130385F36063034303030305C06617563766D6E")

	var nfc *NfcSession

	{
		var transceiver *MockTransceiver = new(MockTransceiver)

		// add in expected request/response tuples
		transceiver.AddReqRsp("0CA4020C1D8711011D35E7EB510E21A0DD12380D9AD2B92D8E0828CB68B81D3FAFC000", "990290008E08E083EAA61ADABFCE9000")
		transceiver.AddReqRsp("0CB000000D9701048E084AFC933E0CDBE5F000", "871101D8059A9CF835105082CA2B1837E4AEC0990290008E08B36DB56761D706BB9000")
		transceiver.AddReqRsp("0CB000040D9701168E0811F7EFC907D1F27400", "87210142E919C115FAF69350B01813D77A9E8D91912A7F717AFD073F199070E61B79C6990290008E083382E3D983F441369000")

		nfc = NewNfcSession(transceiver)
	}

	var err error

	nfc.sm, err = NewSecureMessaging(AES, HexToBytes("74B94F408BBB2CD92571FD5B6370A94CCE7A2FA42AE3EB4DA47B97CE6EAA24C6"), HexToBytes("9E28D5D9FF1D979BE752E8926BF0E1D35A440FC0AEFC4AA3BC5610055AC8B113"))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	nfc.sm.SetSSC(HexToBytes("00000000000000000000000000000020"))

	// Read EF.COM
	actEfComData := nfc.ReadFile(MRTDFileIdEFCOM)

	if !bytes.Equal(actEfComData, expEfComData) {
		t.Errorf("Incorrect EF.COM data (Exp:%x, Act:%x)", expEfComData, actEfComData)
	}

	if !bytes.Equal(nfc.sm.ssc, HexToBytes("00000000000000000000000000000026")) {
		t.Errorf("Incorrect SSC")
	}
}

func TestGetChallengeHappy(t *testing.T) {
	var nfc *NfcSession = NewNfcSession(&StaticTransceiver{HexToBytes("0123456789ABCDEF9000")})

	challenge, err := nfc.GetChallenge(8)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if !bytes.Equal(challenge, HexToBytes("0123456789ABCDEF")) {
		t.Errorf("Challenge differs to expected")
	}
}

func TestGetChallengeUnhappyNoRsp(t *testing.T) {
	var nfc *NfcSession = NewNfcSession(&StaticTransceiver{nil})

	_, err := nfc.GetChallenge(8)

	if err == nil {
		t.Errorf("Error expected")
	}
}

func TestGetChallengeUnhappyErrorStatus(t *testing.T) {
	var nfc *NfcSession = NewNfcSession(&StaticTransceiver{HexToBytes("6FFF")}) // card dead

	_, err := nfc.GetChallenge(8)

	if err == nil {
		t.Errorf("Error expected")
	}
}

func TestGetChallengeUnhappyRspLength(t *testing.T) {
	var nfc *NfcSession = NewNfcSession(&StaticTransceiver{HexToBytes("0123456789ABCDEF119000")}) // 9 bytes instead of 8

	_, err := nfc.GetChallenge(8)

	if err == nil {
		t.Errorf("Error expected")
	}
}

func TestExternalAuthenticateHappy(t *testing.T) {
	var nfc *NfcSession = NewNfcSession(&StaticTransceiver{HexToBytes("0123456789ABCDEF01239000")})

	rspBytes, err := nfc.ExternalAuthenticate(HexToBytes("01234567"), 10)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if !bytes.Equal(rspBytes, HexToBytes("0123456789ABCDEF0123")) {
		t.Errorf("Response differs to expected")
	}
}

func TestExternalAuthenticateUnhappyNoRsp(t *testing.T) {
	var nfc *NfcSession = NewNfcSession(&StaticTransceiver{nil})

	_, err := nfc.ExternalAuthenticate(HexToBytes("01234567"), 10)

	if err == nil {
		t.Errorf("Error expected")
	}
}

func TestExternalAuthenticateUnhappyErrorStatus(t *testing.T) {
	var nfc *NfcSession = NewNfcSession(&StaticTransceiver{HexToBytes("6FFF")}) // card dead

	_, err := nfc.ExternalAuthenticate(HexToBytes("01234567"), 10)

	if err == nil {
		t.Errorf("Error expected")
	}
}

func TestExternalAuthenticateUnhappyRspLength(t *testing.T) {
	var nfc *NfcSession = NewNfcSession(&StaticTransceiver{HexToBytes("0123456789ABCDEF019000")}) // 9 bytes instead of 10

	_, err := nfc.ExternalAuthenticate(HexToBytes("01234567"), 10)

	if err == nil {
		t.Errorf("Error expected")
	}
}

// TODO - the above (and others) should be table based tests
//			GetChallenge
//			ExternalAuthenticate

func TestSelectMF(t *testing.T) {
	testCases := []struct {
		transceiver Transceiver
		expError    bool
	}{
		{
			// happy - success
			transceiver: &StaticTransceiver{HexToBytes("9000")},
			expError:    false,
		},
		{
			// unhappy - empty response
			transceiver: &StaticTransceiver{nil},
			expError:    true,
		},
		{
			// unhappy - card dead response
			transceiver: &StaticTransceiver{HexToBytes("6FFF")},
			expError:    true,
		},
	}
	for _, tc := range testCases {
		var nfc *NfcSession = NewNfcSession(tc.transceiver)

		err := nfc.SelectMF()

		if tc.expError != (err != nil) {
			t.Errorf("Error state differs to expected (Exp:%t) (Act:%t)", tc.expError, (err != nil))
		}
	}
}

func TestSelectEF(t *testing.T) {
	testCases := []struct {
		fileId      uint16
		transceiver Transceiver
		expError    bool
		expSelected bool
	}{
		{
			// happy - success
			fileId:      0x0101,
			transceiver: &StaticTransceiver{HexToBytes("9000")},
			expError:    false,
			expSelected: true,
		},
		{
			// happy - file not found
			fileId:      0x0101,
			transceiver: &StaticTransceiver{HexToBytes("6A82")},
			expError:    false,
			expSelected: false,
		},
		{
			// unhappy - empty response
			fileId:      0x0101,
			transceiver: &StaticTransceiver{nil},
			expError:    true,
			expSelected: false,
		},
		{
			// unhappy - card dead response
			fileId:      0x0101,
			transceiver: &StaticTransceiver{HexToBytes("6FFF")},
			expError:    true,
			expSelected: false,
		},
	}
	for _, tc := range testCases {
		var nfc *NfcSession = NewNfcSession(tc.transceiver)

		selected, err := nfc.SelectEF(tc.fileId)

		if tc.expError != (err != nil) {
			t.Errorf("Error state differs to expected (Exp:%t) (Act:%t)", tc.expError, (err != nil))
		}

		if tc.expSelected != selected {
			t.Errorf("Selected state differs to expected (Exp:%t) (Act:%t)", tc.expSelected, selected)
		}
	}
}

func TestSelectAid(t *testing.T) {
	testCases := []struct {
		aid         []byte
		transceiver Transceiver
		expError    bool
		expSelected bool
	}{
		{
			// happy - success
			aid:         []byte("A0000002471001"),
			transceiver: &StaticTransceiver{HexToBytes("9000")},
			expError:    false,
			expSelected: true,
		},
		{
			// happy - file not found
			aid:         []byte("A0000002471001"),
			transceiver: &StaticTransceiver{HexToBytes("6A82")},
			expError:    false,
			expSelected: false,
		},
		{
			// unhappy - empty response
			aid:         []byte("A0000002471001"),
			transceiver: &StaticTransceiver{nil},
			expError:    true,
			expSelected: false,
		},
		{
			// unhappy - card dead response
			aid:         []byte("A0000002471001"),
			transceiver: &StaticTransceiver{HexToBytes("6FFF")},
			expError:    true,
			expSelected: false,
		},
	}
	for _, tc := range testCases {
		var nfc *NfcSession = NewNfcSession(tc.transceiver)

		selected, err := nfc.SelectAid(tc.aid)

		if tc.expError != (err != nil) {
			t.Errorf("Error state differs to expected (Exp:%t) (Act:%t)", tc.expError, (err != nil))
		}

		if tc.expSelected != selected {
			t.Errorf("Selected state differs to expected (Exp:%t) (Act:%t)", tc.expSelected, selected)
		}
	}
}
