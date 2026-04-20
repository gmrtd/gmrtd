package reader

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/utils"
)

type MockStatus struct{}

func (s *MockStatus) Status(_ string) {
	// NB do nothing
}

func EmptyCscaTrustStore(t *testing.T) cms.CertPool {
	t.Helper()

	return &cms.GenericCertPool{}
}

func TestReaderSetup(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.MockTransceiver{})
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))

	if reader.skipPace {
		t.Errorf("Reader should default to PACE=Yes")
	}

	reader.SkipPace()

	if !reader.skipPace {
		t.Errorf("Reader should now have PACE=NO")
	}
}

func TestRecordAtrAts(t *testing.T) {
	var expAtr []byte = utils.HexToBytes("1234567890")
	var expAts []byte = utils.HexToBytes("ABCDEF")

	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.MockTransceiver{})
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(expAtr, expAts, password)

	err := recordAtrAts(reader, state)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	// verify that ATR was recorded
	if !bytes.Equal(state.docEx.Session.ChipActivationRsp.Atr, expAtr) {
		t.Errorf("ATR differs to expected (act:%X) (exp:%X)", state.docEx.Session.ChipActivationRsp.Atr, expAtr)
	}

	// verify that ATS was recorded
	if !bytes.Equal(state.docEx.Session.ChipActivationRsp.Ats, expAts) {
		t.Errorf("ATS differs to expected (act:%X) (exp:%X)", state.docEx.Session.ChipActivationRsp.Ats, expAts)
	}
}

func TestReadLDS1DgsFilesNotFound(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6A82")}) // 6A82: file not found
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)
	var err error

	sodBytes := utils.HexToBytes("778209C5308209C106092A864886F70D010702A08209B2308209AE020103310D300B0609608648016503040201308201210606678108010101A0820115048201113082010D020101300B06096086480165030402013081EA302502010104208FA1F1B3F615AE683384A265EB321054AD974FEB90EC8A87311695996D80F61C302502010204202CC691A10F9F130DD092F36AFC6D04D1BB50386F1C757822AA7EEE93E340C06630250201030420DB17E0157E92A19D01492E87637D32CC3F7CA2D37B09E25063D4C787B25349183025020104042043E3EE196D699D5190F42E0FC28E83FB79784D4BD8F5FE78F39064B82A36CBF7302502010D0420ECE32CDFA98B532A9544AC359A10A510371D1C05BB766700948CB07719E1E3FB302502010E04209CDA75E7B4F6168E6586CCD175C0AAB3E90F47A68D68E922122937414A90622D300E1304303130381306303430303030A08206603082065C30820410A00302010202045FCDCC69304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203060310B30090603550406130253473121301F060355040A0C184D696E6973747279206F6620486F6D652041666661697273310C300A060355040B0C034943413120301E06035504030C1753696E6761706F72652050617373706F72742043412035301E170D3232303932373032333631325A170D3333303232373135303834315A305D310B30090603550406130253473121301F060355040A0C184D696E6973747279206F6620486F6D652041666661697273310C300A060355040B0C03494341311D301B06035504030C1453472044534331302032303232303932372D303130820122300D06092A864886F70D01010105000382010F003082010A0282010100AB3BABCE4F47AA14EED435CA172DA236DC346AE818BF16EA5EB0EBD5DC865FFF89A1F7B41E1D505681F1FF6B64088726CA334A35A7E8F47164C36A3D5A3A2F342BC99594615F28B205C8A4231D0EC189C3F1716F9D0F55D42D25CEF87FE5241DA271F05F8E26486B4E656F1DB0F532D5873D0D8DF27B2F46F008D7C360526C1143B9CA395CFA2DCF9AD0EB4435D107FFE5F7FDB3256FE003435B97E49522518E6A0431E1BDD5534B9184D0891CEFA5E368930DE14626BEEC73E7C08534B1C3D35DB0319F50DAC8E43A21546A9D2269D5C454CCE6D4D3AF5BDFEC5CC44B74140103E5FF515E4F9F8B5424C73CB77773CE0A566B84A5051B82635EDBB1110E70DB0203010001A38201B7308201B3300E0603551D0F0101FF0404030207803015060767810801010602040A30080201003103130150301B0603551D1204143012A410300E310C300A06035504070C03534750301B0603551D1104143012A410300E310C300A06035504070C035347503081E20603551D1F0481DA3081D7305CA05AA058862A68747470733A2F2F706B64646F776E6C6F6164312E6963616F2E696E742F43524C732F5347502E63726C862A68747470733A2F2F706B64646F776E6C6F6164322E6963616F2E696E742F43524C732F5347502E63726C3077A075A073A471306F310B30090603550406130253473121301F060355040A0C184D696E6973747279206F6620486F6D652041666661697273310C300A060355040B0C034943413120301E06035504030C1753696E6761706F72652050617373706F72742043412035310D300B06035504030C0443524C31302B0603551D1004243022800F32303232303932373032333631325A810F32303233303232373135303834315A301F0603551D2304183016801484CD5D8A477755058D4EC97E0D4992322BE1C545301D0603551D0E0416041410274D05FE684E95BAA3C265FE8A65CDBCC185F4304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201200382020100A95576A7F29F4C1CC5E24314B0765E043D39562BCED927F2AC1ECE0D57A81EA2B6C106C75EF154D606AD06B00829651D139BB0F9BF3647E0C1EB3940F38C297F0617FBD0EB487E6247677374C727E750317437F93EE79ABA5ECFCA63BB92E900A74FD14A925E00780D41E47386D619B0185352F183A8A07132E86C4119F6AD804DD275EB7F64DA170F3FD77A457E4330E2EFB9EA7B1D06001ACA7FFB0AB82C5EA3FC0D510E60D4F6A44DABCFD40682B9B44D07F30CA4C02DC8206422F52036A728BABFC847CBC15D44B766412875E9797D08ADE79B1F8AB61D44E7E4DFC583FE09FB6CFAE10D953BCBECFB9073D2F94CF3EC94D987CC83BFAE02E2CC723E8A49C08EF1407AA0429428CF48DA18745785D29DE8E38310DCD9F3B76028D25A7B9858D3500B51B694EFBCD660216EF6766CA7685E6C0225DD5090DD2A370B96D3745983A4FF5B0704F6ADB97489BDBE823049E21B9F6D514B448DA18B1F98569EE75938598C0585CEC7DA852264DFCA9715A201DB1E46F56D8D33311FA056B3A61468E835CA444A029E59DFB235242588A9D1FA0FDC527656FFFEF18B0E1723346F77CF75929A30BCB0461CFCE1608135FA62E056D61AA8A0BAEB4E359B9BE69AEB538144583454CF973BB7362E104BF55EF6DC6E69131F3380940E15E7256CFECAAE812FB984540E79D83B1F466917508E46B51F6DEB468F375901B4D79CEAEDCA3182020F3082020B02010130683060310B30090603550406130253473121301F060355040A0C184D696E6973747279206F6620486F6D652041666661697273310C300A060355040B0C034943413120301E06035504030C1753696E6761706F72652050617373706F7274204341203502045FCDCC69300B0609608648016503040201A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420985BA4E3CF3921358F9D742C74B4946451D3099C4DC35DF338E7DC9994BDC27C304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A203020120048201005488B562ADB63391C274AF842DD58243266AABEA01C52FA24C93052796E1621EEC251740BC33241C4947A3D0F3A2CD9637F8BCCACA2D57D1AFB1164C96D4FEA242F271A265A9FA15E37BAC8D6829323CA3DCC21A169F37EF2628204A242D3F121A2A21B45471E5A71EDAC221D0258ED1DF132179734CC565F46DAD9959A7EA7FEB2BA4B92A3830E64E8FB45FDBC42759FFFF3CECB6C6FF3FAF71FB45E084309324DBB8D39DD1111A9E7681F64D14FEE679ECCB9B7A756174FC7CB49BDA3EF5FF678A1A35068CAE83B92A4C1B96097317E4ED14C43932EF62D916480E5A64D66DA7529D8291F15C5EF8B76286CEFD82A23D3502C5404ACC1C45F3AF3DCA7B8190")
	state.docEx.Document.Mf.Lds1.Sod, err = document.NewSOD(sodBytes)
	if err != nil {
		t.Fatalf("Unexpected error: NewSOD: %s", err)
	}

	// NB no errors expected
	err = readLDS1dgs(reader, state)
	if err != nil {
		t.Errorf("Unexpected error: readLDS1files: %s", err)
	}
}

func TestReadEfSodFileNotFound(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6A82")}) // 6A82: file not found
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	err := readEfSod(reader, state)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
}

func TestReadEfSodCardDeadError(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6FFF")}) // 6FFF: card dead
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	err := readEfSod(reader, state)
	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestReadEfComFileNotFound(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6A82")}) // 6A82: file not found
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	err := readEfCom(reader, state)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
}

func TestReadEfComCardDeadError(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6FFF")}) // 6FFF: card dead
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	err := readEfCom(reader, state)
	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestReadEfDirFileNotFound(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6A82")}) // 6A82: file not found
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	err := readEfDir(reader, state)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
}

func TestReadEfDirCardDeadError(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6FFF")}) // 6FFF: card dead
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	err := readEfDir(reader, state)
	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestReadEfCardAccessFileNotFound(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6A82")}) // 6A82: file not found
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	err := readEfCardAccess(reader, state)

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
}

func TestReadEfCardAccessCardDeadError(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6FFF")}) // 6FFF: card dead
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	err := readEfCardAccess(reader, state)

	if err == nil {
		t.Errorf("Expected error")
	}
}

type PanicTransceiver struct {
	P any
}

func (t *PanicTransceiver) Transceive(cla, ins, p1, p2 int, data []byte, le int, rapdu []byte) []byte {
	panic(t.P)
}

func TestReadDocumentTransceiverPanicIsHandled(t *testing.T) {
	cases := []struct {
		name  string
		panic any
	}{
		{"panic:string", "Transceiver that always panics"},
		{"panic:error", fmt.Errorf("Transceiver that always panics")},
		{"panic:other", []byte{1, 2, 3, 4, 5}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var status MockStatus
			var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&PanicTransceiver{P: tc.panic})
			reader := NewReader(&status, nfc, EmptyCscaTrustStore(t))
			pass := password.NewPasswordCan("123456")

			_, err := reader.ReadDocument(pass, nil, nil)
			if err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}
