package reader

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/pace"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/utils"
)

// MockStatus records the status updates it receives, so tests can assert on them.
// NB guarded by a mutex because TestReaderConcurrentAccess shares one instance.
type MockStatus struct {
	mu       sync.Mutex
	statuses []Status
}

func (s *MockStatus) Status(status Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statuses = append(s.statuses, status)
}

func (s *MockStatus) Recorded() []Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Status(nil), s.statuses...)
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

func TestWithAAChallenge(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.MockTransceiver{})

	t.Run("valid 8 bytes", func(t *testing.T) {
		reader, err := NewReader(&status, nfc, EmptyCscaTrustStore(t)).WithAAChallenge(make([]byte, 8))
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if reader == nil {
			t.Errorf("expected non-nil reader")
		}
	})

	invalidSizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"7 bytes", 7},
		{"9 bytes", 9},
		{"16 bytes", 16},
	}
	for _, tc := range invalidSizes {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewReader(&status, nfc, EmptyCscaTrustStore(t)).WithAAChallenge(make([]byte, tc.size))
			if err == nil {
				t.Errorf("expected error for challenge of length %d", tc.size)
			}
		})
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

func TestReadLDS1DgsMissingSOD(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&PanicTransceiver{P: "will panic if called"})
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)
	var err error

	err = readLDS1dgs(reader, state)
	if err == nil {
		t.Errorf("Expected error")
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

func TestReadLDS1DgsSkipImages(t *testing.T) {
	// verify that DG2/DG7 are not read when skipImages is set
	// PanicTransceiver panics on any APDU, so if any file read is attempted the test fails
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&PanicTransceiver{P: "no file reads expected when skipImages is set"})
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	state.docEx.Document.Mf.Lds1.Sod = &document.SOD{
		LdsSecurityObject: &document.LDSSecurityObject{
			DataGroupHashValues: []document.DataGroupHash{
				{DataGroupNumber: 2},
				{DataGroupNumber: 7},
			},
		},
	}

	reader.SkipImages()

	err := readLDS1dgs(reader, state)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
}

func TestSelectMF(t *testing.T) {
	var mockTransceiver iso7816.MockTransceiver
	// SELECT MF command
	mockTransceiver.AddReqRsp("00a4000c023f00", "9000")

	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&mockTransceiver)
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	err := selectMF(reader, state)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
}

func TestSelectMFToleratesError(t *testing.T) {
	// NB the selectMF reader-step tolerates any error from nfc.SelectMF (e.g. an unrecognised
	// vendor-specific status here, or the chip being otherwise unreachable) since selecting the
	// MF is not essential - a genuinely dead/unreachable chip will instead fail clearly on a
	// later step.
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6FFF")})
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	err := selectMF(reader, state)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
}

func TestSelectMrtdApplication(t *testing.T) {
	var mockTransceiver iso7816.MockTransceiver
	// SELECT MRTD AID command
	mockTransceiver.AddReqRsp("00a4040c07a0000002471001", "9000")

	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&mockTransceiver)
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	err := selectMrtdApplication(reader, state)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
}

func TestSelectMrtdApplicationFileNotFound(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6A82")}) // 6A82: file not found
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	err := selectMrtdApplication(reader, state)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}
}

func TestSelectMrtdApplicationCardDeadError(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6FFF")}) // 6FFF: card dead
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	err := selectMrtdApplication(reader, state)
	if err == nil {
		t.Errorf("Expected error")
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

func TestReadEfSodInvalidFileContent(t *testing.T) {
	var transceiver iso7816.MockTransceiver

	// setup the transceiver to allow the file to be selected, and read
	// - however, the file does not contain valid data

	// select file
	transceiver.AddReqRsp(
		"00a4020c02011d",
		"9000",
	)

	// read binary (first 4 bytes)
	transceiver.AddReqRsp(
		"00b0000004",
		"011000019000",
	)

	// read binary (next 12 bytes, from offset 4)
	transceiver.AddReqRsp(
		"00b000040e",
		"02030405060708090A0B0C0D0E0F9000",
	)

	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&transceiver)
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

func TestReadEfComInvalidFileContent(t *testing.T) {
	var transceiver iso7816.MockTransceiver

	// setup the transceiver to allow the file to be selected, and read
	// - however, the file does not contain valid data

	// select file
	transceiver.AddReqRsp(
		"00a4020c02011e",
		"9000",
	)

	// read binary (first 4 bytes)
	transceiver.AddReqRsp(
		"00b0000004",
		"011000019000",
	)

	// read binary (next 12 bytes, from offset 4)
	transceiver.AddReqRsp(
		"00b000040e",
		"02030405060708090A0B0C0D0E0F9000",
	)

	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&transceiver)
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

func TestReadEfDirInvalidFileContent(t *testing.T) {
	var transceiver iso7816.MockTransceiver

	// setup the transceiver to allow the file to be selected, and read
	// - however, the file does not contain valid data

	// select file
	transceiver.AddReqRsp(
		"00a4020c022f00",
		"9000",
	)

	// read binary (first 4 bytes)
	// note: different to other similar tests as EF.DIR does not have a root tag
	//       - instead we use tag-61 without a child tag-4F(AID) to trigger an error
	transceiver.AddReqRsp(
		"00b0000004",
		"611000019000",
	)

	// read binary (next 12 bytes, from offset 4)
	transceiver.AddReqRsp(
		"00b000040e",
		"02030405060708090A0B0C0D0E0F9000",
	)

	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&transceiver)
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

func TestReadEfCardAccessInvalidFileContent(t *testing.T) {
	var transceiver iso7816.MockTransceiver

	// setup the transceiver to allow the file to be selected, and read
	// - however, the file does not contain valid data

	// select file
	transceiver.AddReqRsp(
		"00a4020c02011c",
		"9000",
	)

	// read binary (first 4 bytes)
	transceiver.AddReqRsp(
		"00b0000004",
		"011000019000",
	)

	// read binary (next 12 bytes, from offset 4)
	transceiver.AddReqRsp(
		"00b000040e",
		"02030405060708090A0B0C0D0E0F9000",
	)

	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&transceiver)
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	err := readEfCardAccess(reader, state)
	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestPerformPaceEmptyDocument(t *testing.T) {
	// note: nothing in the document suggests PACE is supported (ie missing CardAccess file), so it will be silently skipped

	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&PanicTransceiver{P: "will panic if called"})
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	var err error

	err = performPace(reader, state)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if state.docEx.Session.PaceErr != nil {
		t.Fatalf("Pace error NOT expected (err: %s)", state.docEx.Session.PaceErr)
	}

	if state.docEx.Session.PaceResult != nil {
		t.Fatalf("PaceResult NOT expected")
	}
}

func TestPerformPaceTransceiverError(t *testing.T) {
	// note: valid CardAccess with PACE indicated, but transceiver error occurs

	var err error

	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6FFF")}) // 6FFF: card dead
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))

	var pass *password.Password
	pass, err = password.NewPasswordMrzi("123456", "100101", "301225")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	var state *ReaderState = NewReaderState(nil, nil, pass)

	// valid CardAccess from SG passport
	var cardAccessBytes []byte = utils.HexToBytes("31143012060A04007F0007020204020402010202010D")

	// setup CardAccess file that indicates PACE is supported
	state.docEx.Document.Mf.CardAccess, err = document.NewCardAccess(cardAccessBytes)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	err = performPace(reader, state)
	if err == nil {
		t.Fatalf("expected PACE error to be returned (fail-closed default)")
	}

	if state.docEx.Session.PaceErr == nil {
		t.Fatalf("Pace error expected")
	}

	if !errors.Is(err, state.docEx.Session.PaceErr) {
		t.Fatalf("returned error should wrap PaceErr; got %v", err)
	}

	if state.docEx.Session.PaceResult == nil {
		t.Fatalf("PaceResult expected")
	}

	if state.docEx.Session.PaceResult.Success {
		t.Fatalf("PaceResult FAILURE expected")
	}
}

func TestPerformPaceAllowsBacFallbackOnPaceError(t *testing.T) {
	// Same transceiver failure as TestPerformPaceTransceiverError, but with
	// AllowBacFallbackOnPaceError so the historical BAC-fallback path remains.

	var err error

	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6FFF")}) // 6FFF: card dead
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	reader.AllowBacFallbackOnPaceError()

	var pass *password.Password
	pass, err = password.NewPasswordMrzi("123456", "100101", "301225")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	var state *ReaderState = NewReaderState(nil, nil, pass)

	var cardAccessBytes []byte = utils.HexToBytes("31143012060A04007F0007020204020402010202010D")
	state.docEx.Document.Mf.CardAccess, err = document.NewCardAccess(cardAccessBytes)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	err = performPace(reader, state)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if state.docEx.Session.PaceErr == nil {
		t.Fatalf("Pace error expected to be recorded")
	}

	if state.docEx.Session.PaceResult == nil {
		t.Fatalf("PaceResult expected")
	}

	if state.docEx.Session.PaceResult.Success {
		t.Fatalf("PaceResult FAILURE expected")
	}
}

func TestPerformPaceFallsBackWhenPaceUnsupportedLocally(t *testing.T) {
	// CardAccess advertises PACE with proprietary domain parameters (id 32), which this reader
	// does not implement. No PACE command may be sent (PanicTransceiver), and the default
	// fail-closed policy must not refuse the read: performPace continues to BAC and records
	// the reason in Session.PaceErr.

	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&PanicTransceiver{P: "no PACE command expected"})
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))

	pass, err := password.NewPasswordMrzi("123456", "100101", "301225")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	var state *ReaderState = NewReaderState(nil, nil, pass)

	var cardAccessBytes []byte = utils.HexToBytes("31143012060A04007F00070202040204020102020120")
	state.docEx.Document.Mf.CardAccess, err = document.NewCardAccess(cardAccessBytes)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	err = performPace(reader, state)
	if err != nil {
		t.Fatalf("expected fallback to BAC, got error: %s", err)
	}

	if !errors.Is(state.docEx.Session.PaceErr, pace.ErrPACEUnsupportedLocally) {
		t.Fatalf("PaceErr should record ErrPACEUnsupportedLocally; got %v", state.docEx.Session.PaceErr)
	}
}

func TestPerformPaceSkipPace(t *testing.T) {
	// note: skip pace indicated, even though CardAccess present and indicates PACE

	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&PanicTransceiver{P: "will panic if called"})
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	// valid CardAccess from SG passport
	var cardAccessBytes []byte = utils.HexToBytes("31143012060A04007F0007020204020402010202010D")

	var err error

	// setup CardAccess file that indicates PACE is supported
	state.docEx.Document.Mf.CardAccess, err = document.NewCardAccess(cardAccessBytes)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	// SKIP pace
	reader.SkipPace()

	err = performPace(reader, state)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if state.docEx.Session.PaceErr != nil {
		t.Fatalf("Pace error NOT expected (err: %s)", state.docEx.Session.PaceErr)
	}

	if state.docEx.Session.PaceResult != nil {
		t.Fatalf("PaceResult NOT expected")
	}
}

func TestPerformChipAuthenticationForEmptyDocument(t *testing.T) {
	// note: nothing in the document suggests CA/AA are supported, so they will be silently skipped

	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&PanicTransceiver{P: "will panic if called"})
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	var err error

	err = performChipAuthentication(reader, state)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if state.docEx.Session.ChipAuthErr != nil {
		t.Fatalf("ChipAuth error NOT expected (err: %s)", state.docEx.Session.ChipAuthErr)
	}

	if state.docEx.Session.ChipAuthResult != nil {
		t.Fatalf("ChipAuthResult NOT expected")
	}

	if state.docEx.Session.ActiveAuthErr != nil {
		t.Fatalf("ActiveAuth error NOT expected (err: %s)", state.docEx.Session.ActiveAuthErr)
	}

	if state.docEx.Session.ActiveAuthResult != nil {
		t.Fatalf("ActiveAuthResult NOT expected")
	}
}

func TestPerformPassiveAuthentication(t *testing.T) {
	var expCertChain [][]byte = [][]byte{
		utils.HexToBytes("3082065c30820410a00302010202045fcdcc69304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a2030201203060310b30090603550406130253473121301f060355040a0c184d696e6973747279206f6620486f6d652041666661697273310c300a060355040b0c034943413120301e06035504030c1753696e6761706f72652050617373706f72742043412035301e170d3232303932373032333631325a170d3333303232373135303834315a305d310b30090603550406130253473121301f060355040a0c184d696e6973747279206f6620486f6d652041666661697273310c300a060355040b0c03494341311d301b06035504030c1453472044534331302032303232303932372d303130820122300d06092a864886f70d01010105000382010f003082010a0282010100ab3babce4f47aa14eed435ca172da236dc346ae818bf16ea5eb0ebd5dc865fff89a1f7b41e1d505681f1ff6b64088726ca334a35a7e8f47164c36a3d5a3a2f342bc99594615f28b205c8a4231d0ec189c3f1716f9d0f55d42d25cef87fe5241da271f05f8e26486b4e656f1db0f532d5873d0d8df27b2f46f008d7c360526c1143b9ca395cfa2dcf9ad0eb4435d107ffe5f7fdb3256fe003435b97e49522518e6a0431e1bdd5534b9184d0891cefa5e368930de14626beec73e7c08534b1c3d35db0319f50dac8e43a21546a9d2269d5c454cce6d4d3af5bdfec5cc44b74140103e5ff515e4f9f8b5424c73cb77773ce0a566b84a5051b82635edbb1110e70db0203010001a38201b7308201b3300e0603551d0f0101ff0404030207803015060767810801010602040a30080201003103130150301b0603551d1204143012a410300e310c300a06035504070c03534750301b0603551d1104143012a410300e310c300a06035504070c035347503081e20603551d1f0481da3081d7305ca05aa058862a68747470733a2f2f706b64646f776e6c6f6164312e6963616f2e696e742f43524c732f5347502e63726c862a68747470733a2f2f706b64646f776e6c6f6164322e6963616f2e696e742f43524c732f5347502e63726c3077a075a073a471306f310b30090603550406130253473121301f060355040a0c184d696e6973747279206f6620486f6d652041666661697273310c300a060355040b0c034943413120301e06035504030c1753696e6761706f72652050617373706f72742043412035310d300b06035504030c0443524c31302b0603551d1004243022800f32303232303932373032333631325a810f32303233303232373135303834315a301f0603551d2304183016801484cd5d8a477755058d4ec97e0d4992322be1c545301d0603551d0e0416041410274d05fe684e95baa3c265fe8a65cdbcc185f4304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a2030201200382020100a95576a7f29f4c1cc5e24314b0765e043d39562bced927f2ac1ece0d57a81ea2b6c106c75ef154d606ad06b00829651d139bb0f9bf3647e0c1eb3940f38c297f0617fbd0eb487e6247677374c727e750317437f93ee79aba5ecfca63bb92e900a74fd14a925e00780d41e47386d619b0185352f183a8a07132e86c4119f6ad804dd275eb7f64da170f3fd77a457e4330e2efb9ea7b1d06001aca7ffb0ab82c5ea3fc0d510e60d4f6a44dabcfd40682b9b44d07f30ca4c02dc8206422f52036a728babfc847cbc15d44b766412875e9797d08ade79b1f8ab61d44e7e4dfc583fe09fb6cfae10d953bcbecfb9073d2f94cf3ec94d987cc83bfae02e2cc723e8a49c08ef1407aa0429428cf48da18745785d29de8e38310dcd9f3b76028d25a7b9858d3500b51b694efbcd660216ef6766ca7685e6c0225dd5090dd2a370b96d3745983a4ff5b0704f6adb97489bdbe823049e21b9f6d514b448da18b1f98569ee75938598c0585cec7da852264dfca9715a201db1e46f56d8d33311fa056b3a61468e835ca444a029e59dfb235242588a9d1fa0fdc527656fffef18b0e1723346f77cf75929a30bcb0461cfce1608135fa62e056d61aa8a0baeb4e359b9be69aeb538144583454cf973bb7362e104bf55ef6dc6e69131f3380940e15e7256cfecaae812fb984540e79d83b1f466917508e46b51f6deb468f375901b4d79ceaedca"),
		utils.HexToBytes("3082073e308204f2a003020102020458ed1ee3304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a2030201203060310b30090603550406130253473121301f060355040a0c184d696e6973747279206f6620486f6d652041666661697273310c300a060355040b0c034943413120301e06035504030c1753696e6761706f72652050617373706f72742043412034301e170d3230313231343033323234365a170d3332303431303136303030305a3060310b30090603550406130253473121301f060355040a0c184d696e6973747279206f6620486f6d652041666661697273310c300a060355040b0c034943413120301e06035504030c1753696e6761706f72652050617373706f7274204341203530820222300d06092a864886f70d01010105000382020f003082020a0282020100b687b2fa93ffce2c110051857a65fd68ce3960a260c462af3e9bfa6f269f5ab8965d38cb22ba7f35471ca4b33e7904e183c594d4b9e84c74c04821cf528c3fa83bb6a3f4c0c317e4c95a5acc5339b4c4dd9db8eceb64db29fb88f96525ebde38e48ebe40ffa95b842f16a721e5bae8327d9545e9dc0bd143df441f6f4ed672b1711c6b20e0d266a9866c50eb172ac5dd4530969038d955a7b87bc7656395ddd670c1392672eba4f05e9dc36b563ab3fba1bad9de0ff2df8b1deb562c0ccfe88579d7318e2a6342e6dba73b716c32c830a1f7476b36f80b2dad1f0ce27c9a00610cf4d7f213f35796fc6b26c336fef1db2143dc196c02fde859239dee0bdd459aacd0481ffef9eb1a6d9f52699d570289e3fd2da753195836b2fe51a827ff8ea497059faa496b36831e5554f8f306e835b086e0b7ad30afc1e55d6a15fc1036cf6b54042320747ab7d6d5fc86113937297227758c7cebf21f3827acce909026ceb4ab4d16e065e3bd82dab7ee40abaab58085c96c5f1d19bc16a94b23bf8c0572b7d88b8a4a21a0ae77a231b0bbdaf40d5205e33161a4d8b8722c308d6a565f34f38b50ff84bda8f9ee9f0e584ceac279aa337fbddb9c9b1069a7304955422da53ae35dd72ea2d7827864a698c0980a322b59ba6a4a00dbd115a2f663fafd89413b02f416130875c6bc8e3da4b8bb49c1b6ecfefc1fa2d965fc9e38abd47542030203010001a382019630820192300e0603551d0f0101ff04040302010630120603551d130101ff040830060101ff020100301b0603551d1104143012a410300e310c300a06035504070c03534750301b0603551d1204143012a410300e310c300a06035504070c03534750300d06076781080101060104020500301d0603551d0e0416041484cd5d8a477755058d4ec97e0d4992322be1c5453081e20603551d1f0481da3081d7305ca05aa058862a68747470733a2f2f706b64646f776e6c6f6164312e6963616f2e696e742f43524c732f5347502e63726c862a68747470733a2f2f706b64646f776e6c6f6164322e6963616f2e696e742f43524c732f5347502e63726c3077a075a073a471306f310b30090603550406130253473121301f060355040a0c184d696e6973747279206f6620486f6d652041666661697273310c300a060355040b0c034943413120301e06035504030c1753696e6761706f72652050617373706f72742043412034310d300b06035504030c0443524c31301f0603551d230418301680143a4d8de8fe2407a702bb9f7a320313098a2d4a8d304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012003820201002c1e6f18243012bbfacbb221288f6ae183a002ab685cde0a88cedf8df3fe2db49ca5c095ff77db18be73a73caeea1354c904537b2a03ee3392f70c495e132425072c6d6486dde9ff8d7cb212f4223450c5d95ba65af751960a95f5b83d33afe29edd1bd03013bac1cda14153e7711a2c5f15d5bb705fbf7bf9e82c86194316acb206ea0296fec914adf4a974ceb836942f86f023e5f42dde194712742cf00f510671e4ea67c542e7b9411512f88b24b5f50a2e5f76fefb7f359bc25d2973105622fd15f1db595139d0ea180e2eb49339b42728d86b94b8a32e9efe0c38651f9a135eaf2797a7344038d4f9b7496386a76f4be504a8eafb773a1523a26b2c61fdf57cf09bd97a22845f64477d78e37636b5c370dff16bb13d43eeeea44d6ba0f73d869139b71c921ed04027349a02743883d107d8d06b354dd192a12bedebca30d3b050c1accf0b6323049b6147ceea9dc1a05dbc6aeb7489dbecb1ed889425e48c455b12c45dc277ef59c32944f1feefaf166d80b2886bd477177dc7a11c1bfe87b92c316808cedff831b4851adbded2cb0c8cb46361e6b187082ab57499a38f3e707e3160268e13f89bd40942fccfaba0677313ad6ec4012e6d3206f4ead57731dd1fca98c72143555f0416e4d080d8de8985af6542659ce82facdac3795c8edcb5849e3740e23cc788eac0a8cedb91aa7d9697d07f4ed3a0b98dc6b2135b89"),
	}

	// setup the CSCA trust store with the expected CSCA cert
	var cscaTrustStore cms.GenericCertPool = cms.GenericCertPool{}
	cscaTrustStore.Add(utils.HexToBytes("3082073e308204f2a003020102020458ed1ee3304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a2030201203060310b30090603550406130253473121301f060355040a0c184d696e6973747279206f6620486f6d652041666661697273310c300a060355040b0c034943413120301e06035504030c1753696e6761706f72652050617373706f72742043412034301e170d3230313231343033323234365a170d3332303431303136303030305a3060310b30090603550406130253473121301f060355040a0c184d696e6973747279206f6620486f6d652041666661697273310c300a060355040b0c034943413120301e06035504030c1753696e6761706f72652050617373706f7274204341203530820222300d06092a864886f70d01010105000382020f003082020a0282020100b687b2fa93ffce2c110051857a65fd68ce3960a260c462af3e9bfa6f269f5ab8965d38cb22ba7f35471ca4b33e7904e183c594d4b9e84c74c04821cf528c3fa83bb6a3f4c0c317e4c95a5acc5339b4c4dd9db8eceb64db29fb88f96525ebde38e48ebe40ffa95b842f16a721e5bae8327d9545e9dc0bd143df441f6f4ed672b1711c6b20e0d266a9866c50eb172ac5dd4530969038d955a7b87bc7656395ddd670c1392672eba4f05e9dc36b563ab3fba1bad9de0ff2df8b1deb562c0ccfe88579d7318e2a6342e6dba73b716c32c830a1f7476b36f80b2dad1f0ce27c9a00610cf4d7f213f35796fc6b26c336fef1db2143dc196c02fde859239dee0bdd459aacd0481ffef9eb1a6d9f52699d570289e3fd2da753195836b2fe51a827ff8ea497059faa496b36831e5554f8f306e835b086e0b7ad30afc1e55d6a15fc1036cf6b54042320747ab7d6d5fc86113937297227758c7cebf21f3827acce909026ceb4ab4d16e065e3bd82dab7ee40abaab58085c96c5f1d19bc16a94b23bf8c0572b7d88b8a4a21a0ae77a231b0bbdaf40d5205e33161a4d8b8722c308d6a565f34f38b50ff84bda8f9ee9f0e584ceac279aa337fbddb9c9b1069a7304955422da53ae35dd72ea2d7827864a698c0980a322b59ba6a4a00dbd115a2f663fafd89413b02f416130875c6bc8e3da4b8bb49c1b6ecfefc1fa2d965fc9e38abd47542030203010001a382019630820192300e0603551d0f0101ff04040302010630120603551d130101ff040830060101ff020100301b0603551d1104143012a410300e310c300a06035504070c03534750301b0603551d1204143012a410300e310c300a06035504070c03534750300d06076781080101060104020500301d0603551d0e0416041484cd5d8a477755058d4ec97e0d4992322be1c5453081e20603551d1f0481da3081d7305ca05aa058862a68747470733a2f2f706b64646f776e6c6f6164312e6963616f2e696e742f43524c732f5347502e63726c862a68747470733a2f2f706b64646f776e6c6f6164322e6963616f2e696e742f43524c732f5347502e63726c3077a075a073a471306f310b30090603550406130253473121301f060355040a0c184d696e6973747279206f6620486f6d652041666661697273310c300a060355040b0c034943413120301e06035504030c1753696e6761706f72652050617373706f72742043412034310d300b06035504030c0443524c31301f0603551d230418301680143a4d8de8fe2407a702bb9f7a320313098a2d4a8d304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012003820201002c1e6f18243012bbfacbb221288f6ae183a002ab685cde0a88cedf8df3fe2db49ca5c095ff77db18be73a73caeea1354c904537b2a03ee3392f70c495e132425072c6d6486dde9ff8d7cb212f4223450c5d95ba65af751960a95f5b83d33afe29edd1bd03013bac1cda14153e7711a2c5f15d5bb705fbf7bf9e82c86194316acb206ea0296fec914adf4a974ceb836942f86f023e5f42dde194712742cf00f510671e4ea67c542e7b9411512f88b24b5f50a2e5f76fefb7f359bc25d2973105622fd15f1db595139d0ea180e2eb49339b42728d86b94b8a32e9efe0c38651f9a135eaf2797a7344038d4f9b7496386a76f4be504a8eafb773a1523a26b2c61fdf57cf09bd97a22845f64477d78e37636b5c370dff16bb13d43eeeea44d6ba0f73d869139b71c921ed04027349a02743883d107d8d06b354dd192a12bedebca30d3b050c1accf0b6323049b6147ceea9dc1a05dbc6aeb7489dbecb1ed889425e48c455b12c45dc277ef59c32944f1feefaf166d80b2886bd477177dc7a11c1bfe87b92c316808cedff831b4851adbded2cb0c8cb46361e6b187082ab57499a38f3e707e3160268e13f89bd40942fccfaba0677313ad6ec4012e6d3206f4ead57731dd1fca98c72143555f0416e4d080d8de8985af6542659ce82facdac3795c8edcb5849e3740e23cc788eac0a8cedb91aa7d9697d07f4ed3a0b98dc6b2135b89"))

	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&PanicTransceiver{P: "will panic if called"})
	var reader *Reader = NewReader(&status, nfc, &cscaTrustStore)
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	// valid SOD from SG passport
	var sodBytes []byte = utils.HexToBytes("778209C5308209C106092A864886F70D010702A08209B2308209AE020103310D300B0609608648016503040201308201210606678108010101A0820115048201113082010D020101300B06096086480165030402013081EA302502010104208FA1F1B3F615AE683384A265EB321054AD974FEB90EC8A87311695996D80F61C302502010204202CC691A10F9F130DD092F36AFC6D04D1BB50386F1C757822AA7EEE93E340C06630250201030420DB17E0157E92A19D01492E87637D32CC3F7CA2D37B09E25063D4C787B25349183025020104042043E3EE196D699D5190F42E0FC28E83FB79784D4BD8F5FE78F39064B82A36CBF7302502010D0420ECE32CDFA98B532A9544AC359A10A510371D1C05BB766700948CB07719E1E3FB302502010E04209CDA75E7B4F6168E6586CCD175C0AAB3E90F47A68D68E922122937414A90622D300E1304303130381306303430303030A08206603082065C30820410A00302010202045FCDCC69304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203060310B30090603550406130253473121301F060355040A0C184D696E6973747279206F6620486F6D652041666661697273310C300A060355040B0C034943413120301E06035504030C1753696E6761706F72652050617373706F72742043412035301E170D3232303932373032333631325A170D3333303232373135303834315A305D310B30090603550406130253473121301F060355040A0C184D696E6973747279206F6620486F6D652041666661697273310C300A060355040B0C03494341311D301B06035504030C1453472044534331302032303232303932372D303130820122300D06092A864886F70D01010105000382010F003082010A0282010100AB3BABCE4F47AA14EED435CA172DA236DC346AE818BF16EA5EB0EBD5DC865FFF89A1F7B41E1D505681F1FF6B64088726CA334A35A7E8F47164C36A3D5A3A2F342BC99594615F28B205C8A4231D0EC189C3F1716F9D0F55D42D25CEF87FE5241DA271F05F8E26486B4E656F1DB0F532D5873D0D8DF27B2F46F008D7C360526C1143B9CA395CFA2DCF9AD0EB4435D107FFE5F7FDB3256FE003435B97E49522518E6A0431E1BDD5534B9184D0891CEFA5E368930DE14626BEEC73E7C08534B1C3D35DB0319F50DAC8E43A21546A9D2269D5C454CCE6D4D3AF5BDFEC5CC44B74140103E5FF515E4F9F8B5424C73CB77773CE0A566B84A5051B82635EDBB1110E70DB0203010001A38201B7308201B3300E0603551D0F0101FF0404030207803015060767810801010602040A30080201003103130150301B0603551D1204143012A410300E310C300A06035504070C03534750301B0603551D1104143012A410300E310C300A06035504070C035347503081E20603551D1F0481DA3081D7305CA05AA058862A68747470733A2F2F706B64646F776E6C6F6164312E6963616F2E696E742F43524C732F5347502E63726C862A68747470733A2F2F706B64646F776E6C6F6164322E6963616F2E696E742F43524C732F5347502E63726C3077A075A073A471306F310B30090603550406130253473121301F060355040A0C184D696E6973747279206F6620486F6D652041666661697273310C300A060355040B0C034943413120301E06035504030C1753696E6761706F72652050617373706F72742043412035310D300B06035504030C0443524C31302B0603551D1004243022800F32303232303932373032333631325A810F32303233303232373135303834315A301F0603551D2304183016801484CD5D8A477755058D4EC97E0D4992322BE1C545301D0603551D0E0416041410274D05FE684E95BAA3C265FE8A65CDBCC185F4304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201200382020100A95576A7F29F4C1CC5E24314B0765E043D39562BCED927F2AC1ECE0D57A81EA2B6C106C75EF154D606AD06B00829651D139BB0F9BF3647E0C1EB3940F38C297F0617FBD0EB487E6247677374C727E750317437F93EE79ABA5ECFCA63BB92E900A74FD14A925E00780D41E47386D619B0185352F183A8A07132E86C4119F6AD804DD275EB7F64DA170F3FD77A457E4330E2EFB9EA7B1D06001ACA7FFB0AB82C5EA3FC0D510E60D4F6A44DABCFD40682B9B44D07F30CA4C02DC8206422F52036A728BABFC847CBC15D44B766412875E9797D08ADE79B1F8AB61D44E7E4DFC583FE09FB6CFAE10D953BCBECFB9073D2F94CF3EC94D987CC83BFAE02E2CC723E8A49C08EF1407AA0429428CF48DA18745785D29DE8E38310DCD9F3B76028D25A7B9858D3500B51B694EFBCD660216EF6766CA7685E6C0225DD5090DD2A370B96D3745983A4FF5B0704F6ADB97489BDBE823049E21B9F6D514B448DA18B1F98569EE75938598C0585CEC7DA852264DFCA9715A201DB1E46F56D8D33311FA056B3A61468E835CA444A029E59DFB235242588A9D1FA0FDC527656FFFEF18B0E1723346F77CF75929A30BCB0461CFCE1608135FA62E056D61AA8A0BAEB4E359B9BE69AEB538144583454CF973BB7362E104BF55EF6DC6E69131F3380940E15E7256CFECAAE812FB984540E79D83B1F466917508E46B51F6DEB468F375901B4D79CEAEDCA3182020F3082020B02010130683060310B30090603550406130253473121301F060355040A0C184D696E6973747279206F6620486F6D652041666661697273310C300A060355040B0C034943413120301E06035504030C1753696E6761706F72652050617373706F7274204341203502045FCDCC69300B0609608648016503040201A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420985BA4E3CF3921358F9D742C74B4946451D3099C4DC35DF338E7DC9994BDC27C304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A203020120048201005488B562ADB63391C274AF842DD58243266AABEA01C52FA24C93052796E1621EEC251740BC33241C4947A3D0F3A2CD9637F8BCCACA2D57D1AFB1164C96D4FEA242F271A265A9FA15E37BAC8D6829323CA3DCC21A169F37EF2628204A242D3F121A2A21B45471E5A71EDAC221D0258ED1DF132179734CC565F46DAD9959A7EA7FEB2BA4B92A3830E64E8FB45FDBC42759FFFF3CECB6C6FF3FAF71FB45E084309324DBB8D39DD1111A9E7681F64D14FEE679ECCB9B7A756174FC7CB49BDA3EF5FF678A1A35068CAE83B92A4C1B96097317E4ED14C43932EF62D916480E5A64D66DA7529D8291F15C5EF8B76286CEFD82A23D3502C5404ACC1C45F3AF3DCA7B8190")

	var err error

	state.docEx.Document.Mf.Lds1.Sod, err = document.NewSOD(sodBytes)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	err = performPassiveAuthentication(reader, state)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if state.docEx.Session.PassiveAuthErr != nil {
		t.Fatalf("PassiveAuth error NOT expected (err: %s)", state.docEx.Session.PassiveAuthErr)
	}

	if state.docEx.Session.PassiveAuthResult.Success != true {
		t.Fatalf("Expected SUCCESS")
	}

	if !reflect.DeepEqual(
		expCertChain,
		state.docEx.Session.PassiveAuthResult.Sod.CertChain,
	) {
		t.Fatalf("CertChain differs to expected")
	}
}

func TestPerformPassiveAuthenticationBadSignatureErr(t *testing.T) {
	// as per 'TestPerformPassiveAuthentication', but with signature corrupted to trigger an error

	// setup the CSCA trust store with the expected CSCA cert
	var cscaTrustStore cms.GenericCertPool = cms.GenericCertPool{}
	cscaTrustStore.Add(utils.HexToBytes("3082073e308204f2a003020102020458ed1ee3304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a2030201203060310b30090603550406130253473121301f060355040a0c184d696e6973747279206f6620486f6d652041666661697273310c300a060355040b0c034943413120301e06035504030c1753696e6761706f72652050617373706f72742043412034301e170d3230313231343033323234365a170d3332303431303136303030305a3060310b30090603550406130253473121301f060355040a0c184d696e6973747279206f6620486f6d652041666661697273310c300a060355040b0c034943413120301e06035504030c1753696e6761706f72652050617373706f7274204341203530820222300d06092a864886f70d01010105000382020f003082020a0282020100b687b2fa93ffce2c110051857a65fd68ce3960a260c462af3e9bfa6f269f5ab8965d38cb22ba7f35471ca4b33e7904e183c594d4b9e84c74c04821cf528c3fa83bb6a3f4c0c317e4c95a5acc5339b4c4dd9db8eceb64db29fb88f96525ebde38e48ebe40ffa95b842f16a721e5bae8327d9545e9dc0bd143df441f6f4ed672b1711c6b20e0d266a9866c50eb172ac5dd4530969038d955a7b87bc7656395ddd670c1392672eba4f05e9dc36b563ab3fba1bad9de0ff2df8b1deb562c0ccfe88579d7318e2a6342e6dba73b716c32c830a1f7476b36f80b2dad1f0ce27c9a00610cf4d7f213f35796fc6b26c336fef1db2143dc196c02fde859239dee0bdd459aacd0481ffef9eb1a6d9f52699d570289e3fd2da753195836b2fe51a827ff8ea497059faa496b36831e5554f8f306e835b086e0b7ad30afc1e55d6a15fc1036cf6b54042320747ab7d6d5fc86113937297227758c7cebf21f3827acce909026ceb4ab4d16e065e3bd82dab7ee40abaab58085c96c5f1d19bc16a94b23bf8c0572b7d88b8a4a21a0ae77a231b0bbdaf40d5205e33161a4d8b8722c308d6a565f34f38b50ff84bda8f9ee9f0e584ceac279aa337fbddb9c9b1069a7304955422da53ae35dd72ea2d7827864a698c0980a322b59ba6a4a00dbd115a2f663fafd89413b02f416130875c6bc8e3da4b8bb49c1b6ecfefc1fa2d965fc9e38abd47542030203010001a382019630820192300e0603551d0f0101ff04040302010630120603551d130101ff040830060101ff020100301b0603551d1104143012a410300e310c300a06035504070c03534750301b0603551d1204143012a410300e310c300a06035504070c03534750300d06076781080101060104020500301d0603551d0e0416041484cd5d8a477755058d4ec97e0d4992322be1c5453081e20603551d1f0481da3081d7305ca05aa058862a68747470733a2f2f706b64646f776e6c6f6164312e6963616f2e696e742f43524c732f5347502e63726c862a68747470733a2f2f706b64646f776e6c6f6164322e6963616f2e696e742f43524c732f5347502e63726c3077a075a073a471306f310b30090603550406130253473121301f060355040a0c184d696e6973747279206f6620486f6d652041666661697273310c300a060355040b0c034943413120301e06035504030c1753696e6761706f72652050617373706f72742043412034310d300b06035504030c0443524c31301f0603551d230418301680143a4d8de8fe2407a702bb9f7a320313098a2d4a8d304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012003820201002c1e6f18243012bbfacbb221288f6ae183a002ab685cde0a88cedf8df3fe2db49ca5c095ff77db18be73a73caeea1354c904537b2a03ee3392f70c495e132425072c6d6486dde9ff8d7cb212f4223450c5d95ba65af751960a95f5b83d33afe29edd1bd03013bac1cda14153e7711a2c5f15d5bb705fbf7bf9e82c86194316acb206ea0296fec914adf4a974ceb836942f86f023e5f42dde194712742cf00f510671e4ea67c542e7b9411512f88b24b5f50a2e5f76fefb7f359bc25d2973105622fd15f1db595139d0ea180e2eb49339b42728d86b94b8a32e9efe0c38651f9a135eaf2797a7344038d4f9b7496386a76f4be504a8eafb773a1523a26b2c61fdf57cf09bd97a22845f64477d78e37636b5c370dff16bb13d43eeeea44d6ba0f73d869139b71c921ed04027349a02743883d107d8d06b354dd192a12bedebca30d3b050c1accf0b6323049b6147ceea9dc1a05dbc6aeb7489dbecb1ed889425e48c455b12c45dc277ef59c32944f1feefaf166d80b2886bd477177dc7a11c1bfe87b92c316808cedff831b4851adbded2cb0c8cb46361e6b187082ab57499a38f3e707e3160268e13f89bd40942fccfaba0677313ad6ec4012e6d3206f4ead57731dd1fca98c72143555f0416e4d080d8de8985af6542659ce82facdac3795c8edcb5849e3740e23cc788eac0a8cedb91aa7d9697d07f4ed3a0b98dc6b2135b89"))

	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&PanicTransceiver{P: "will panic if called"})
	var reader *Reader = NewReader(&status, nfc, &cscaTrustStore)
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	// valid SOD from SG passport
	var sodBytes []byte = utils.HexToBytes("778209C5308209C106092A864886F70D010702A08209B2308209AE020103310D300B0609608648016503040201308201210606678108010101A0820115048201113082010D020101300B06096086480165030402013081EA302502010104208FA1F1B3F615AE683384A265EB321054AD974FEB90EC8A87311695996D80F61C302502010204202CC691A10F9F130DD092F36AFC6D04D1BB50386F1C757822AA7EEE93E340C06630250201030420DB17E0157E92A19D01492E87637D32CC3F7CA2D37B09E25063D4C787B25349183025020104042043E3EE196D699D5190F42E0FC28E83FB79784D4BD8F5FE78F39064B82A36CBF7302502010D0420ECE32CDFA98B532A9544AC359A10A510371D1C05BB766700948CB07719E1E3FB302502010E04209CDA75E7B4F6168E6586CCD175C0AAB3E90F47A68D68E922122937414A90622D300E1304303130381306303430303030A08206603082065C30820410A00302010202045FCDCC69304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201203060310B30090603550406130253473121301F060355040A0C184D696E6973747279206F6620486F6D652041666661697273310C300A060355040B0C034943413120301E06035504030C1753696E6761706F72652050617373706F72742043412035301E170D3232303932373032333631325A170D3333303232373135303834315A305D310B30090603550406130253473121301F060355040A0C184D696E6973747279206F6620486F6D652041666661697273310C300A060355040B0C03494341311D301B06035504030C1453472044534331302032303232303932372D303130820122300D06092A864886F70D01010105000382010F003082010A0282010100AB3BABCE4F47AA14EED435CA172DA236DC346AE818BF16EA5EB0EBD5DC865FFF89A1F7B41E1D505681F1FF6B64088726CA334A35A7E8F47164C36A3D5A3A2F342BC99594615F28B205C8A4231D0EC189C3F1716F9D0F55D42D25CEF87FE5241DA271F05F8E26486B4E656F1DB0F532D5873D0D8DF27B2F46F008D7C360526C1143B9CA395CFA2DCF9AD0EB4435D107FFE5F7FDB3256FE003435B97E49522518E6A0431E1BDD5534B9184D0891CEFA5E368930DE14626BEEC73E7C08534B1C3D35DB0319F50DAC8E43A21546A9D2269D5C454CCE6D4D3AF5BDFEC5CC44B74140103E5FF515E4F9F8B5424C73CB77773CE0A566B84A5051B82635EDBB1110E70DB0203010001A38201B7308201B3300E0603551D0F0101FF0404030207803015060767810801010602040A30080201003103130150301B0603551D1204143012A410300E310C300A06035504070C03534750301B0603551D1104143012A410300E310C300A06035504070C035347503081E20603551D1F0481DA3081D7305CA05AA058862A68747470733A2F2F706B64646F776E6C6F6164312E6963616F2E696E742F43524C732F5347502E63726C862A68747470733A2F2F706B64646F776E6C6F6164322E6963616F2E696E742F43524C732F5347502E63726C3077A075A073A471306F310B30090603550406130253473121301F060355040A0C184D696E6973747279206F6620486F6D652041666661697273310C300A060355040B0C034943413120301E06035504030C1753696E6761706F72652050617373706F72742043412035310D300B06035504030C0443524C31302B0603551D1004243022800F32303232303932373032333631325A810F32303233303232373135303834315A301F0603551D2304183016801484CD5D8A477755058D4EC97E0D4992322BE1C545301D0603551D0E0416041410274D05FE684E95BAA3C265FE8A65CDBCC185F4304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A2030201200382020100A95576A7F29F4C1CC5E24314B0765E043D39562BCED927F2AC1ECE0D57A81EA2B6C106C75EF154D606AD06B00829651D139BB0F9BF3647E0C1EB3940F38C297F0617FBD0EB487E6247677374C727E750317437F93EE79ABA5ECFCA63BB92E900A74FD14A925E00780D41E47386D619B0185352F183A8A07132E86C4119F6AD804DD275EB7F64DA170F3FD77A457E4330E2EFB9EA7B1D06001ACA7FFB0AB82C5EA3FC0D510E60D4F6A44DABCFD40682B9B44D07F30CA4C02DC8206422F52036A728BABFC847CBC15D44B766412875E9797D08ADE79B1F8AB61D44E7E4DFC583FE09FB6CFAE10D953BCBECFB9073D2F94CF3EC94D987CC83BFAE02E2CC723E8A49C08EF1407AA0429428CF48DA18745785D29DE8E38310DCD9F3B76028D25A7B9858D3500B51B694EFBCD660216EF6766CA7685E6C0225DD5090DD2A370B96D3745983A4FF5B0704F6ADB97489BDBE823049E21B9F6D514B448DA18B1F98569EE75938598C0585CEC7DA852264DFCA9715A201DB1E46F56D8D33311FA056B3A61468E835CA444A029E59DFB235242588A9D1FA0FDC527656FFFEF18B0E1723346F77CF75929A30BCB0461CFCE1608135FA62E056D61AA8A0BAEB4E359B9BE69AEB538144583454CF973BB7362E104BF55EF6DC6E69131F3380940E15E7256CFECAAE812FB984540E79D83B1F466917508E46B51F6DEB468F375901B4D79CEAEDCA3182020F3082020B02010130683060310B30090603550406130253473121301F060355040A0C184D696E6973747279206F6620486F6D652041666661697273310C300A060355040B0C034943413120301E06035504030C1753696E6761706F72652050617373706F7274204341203502045FCDCC69300B0609608648016503040201A048301506092A864886F70D01090331080606678108010101302F06092A864886F70D01090431220420985BA4E3CF3921358F9D742C74B4946451D3099C4DC35DF338E7DC9994BDC27C304106092A864886F70D01010A3034A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165030402010500A203020120048201005488B562ADB63391C274AF842DD58243266AABEA01C52FA24C93052796E1621EEC251740BC33241C4947A3D0F3A2CD9637F8BCCACA2D57D1AFB1164C96D4FEA242F271A265A9FA15E37BAC8D6829323CA3DCC21A169F37EF2628204A242D3F121A2A21B45471E5A71EDAC221D0258ED1DF132179734CC565F46DAD9959A7EA7FEB2BA4B92A3830E64E8FB45FDBC42759FFFF3CECB6C6FF3FAF71FB45E084309324DBB8D39DD1111A9E7681F64D14FEE679ECCB9B7A756174FC7CB49BDA3EF5FF678A1A35068CAE83B92A4C1B96097317E4ED14C43932EF62D916480E5A64D66DA7529D8291F15C5EF8B76286CEFD82A23D3502C5404ACC1C45F3AF3DCA7B8190")

	// ** CORRUPT THE SIGNATURE ** flip the bits on the last byte
	sodBytes[len(sodBytes)-1] ^= 0xff

	var err error

	state.docEx.Document.Mf.Lds1.Sod, err = document.NewSOD(sodBytes)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	err = performPassiveAuthentication(reader, state)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if state.docEx.Session.PassiveAuthErr == nil {
		t.Fatalf("PassiveAuth error expected")
	}

	if state.docEx.Session.PassiveAuthResult.Success != false {
		t.Fatalf("Expected FAILURE")
	}
}

func TestVerifyDocumentEmptyDocErr(t *testing.T) {
	// note: empty document will fail verification, but the step itself is soft-fail -
	// the error is recorded on the session, not returned (see Session.DocumentVerifyErr)

	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&PanicTransceiver{P: "will panic if called"})
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var password *password.Password = password.NewPasswordNil()
	var state *ReaderState = NewReaderState(nil, nil, password)

	var err error

	err = verifyDocument(reader, state)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if state.docEx.Session.DocumentVerifyErr == nil {
		t.Fatalf("expected DocumentVerifyErr to be set")
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

			_, _, err := reader.ReadDocument(pass, nil, nil)
			if err == nil {
				t.Fatalf("expected error")
			}
		})
	}
}

func TestRunSteps(t *testing.T) {
	called := 0

	step := func(r *Reader, s *ReaderState) error {
		called++
		return nil
	}

	err := runSteps(&Reader{}, &ReaderState{}, step, step, step)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	// Ensure steps were executed
	if called != 3 {
		t.Fatalf("expected 3 steps to run, got %d", called)
	}
}

func TestRunStepsError(t *testing.T) {
	expectedErr := errors.New("step failed")

	called := 0

	step1 := func(r *Reader, s *ReaderState) error {
		called++
		return nil
	}

	step2 := func(r *Reader, s *ReaderState) error {
		called++
		return expectedErr
	}

	step3 := func(r *Reader, s *ReaderState) error {
		called++
		return nil // should never be called
	}

	err := runSteps(&Reader{}, &ReaderState{}, step1, step2, step3)

	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	// Verify wrapping
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected wrapped error to contain %v, got %v", expectedErr, err)
	}

	// Optional: verify prefix
	if got := err.Error(); got != "[runSteps] error: step failed" {
		t.Fatalf("unexpected error message: %s", got)
	}

	// Ensure step3 was NOT executed
	if called != 2 {
		t.Fatalf("expected 2 steps to run, got %d", called)
	}
}

// Regression test for a heap-corruption crash observed under concurrent use:
// a shared Reader's fields (skipPace/skipImages/aaChallenge) were written by
// the configuration methods while ReadDocument read them from another
// goroutine, unsynchronised. Run with `go test -race` to confirm the mutex
// added to Reader closes the race - without it, this reliably trips the race
// detector (and, in production, can corrupt the Go heap).
func TestReaderConcurrentAccess(t *testing.T) {
	var status MockStatus
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6A82")}) // 6A82: file not found
	var reader *Reader = NewReader(&status, nfc, EmptyCscaTrustStore(t))
	var pass *password.Password = password.NewPasswordNil()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reader.SkipPace()
			reader.SkipImages()
			_, _ = reader.WithAAChallenge(make([]byte, 8))
			_, _, _ = reader.ReadDocument(pass, nil, nil) // expected to fail fast (file not found)
		}()
	}
	wg.Wait()
}

func trustedState(t *testing.T) *ReaderState {
	t.Helper()
	state := NewReaderState(nil, nil, password.NewPasswordNil())
	state.docEx.Session.PassiveAuthResult = &document.PassiveAuthResult{Success: true, CardSec: &document.PassiveAuth{}}
	return state
}

func requireAuthenticReader(t *testing.T, transceiver iso7816.Transceiver) *Reader {
	t.Helper()
	var status MockStatus
	reader := NewReader(&status, iso7816.NewNfcSession(transceiver), EmptyCscaTrustStore(t))
	reader.RequireAuthenticDocument()
	return reader
}

func TestRequireAuthenticDocumentDefaultOff(t *testing.T) {
	var status MockStatus
	reader := NewReader(&status, iso7816.NewNfcSession(&iso7816.MockTransceiver{}), EmptyCscaTrustStore(t))
	state := NewReaderState(nil, nil, password.NewPasswordNil())
	state.docEx.Session.ActiveAuthErr = errors.New("AA failed")

	if err := checkAuthenticDocument(reader, state); err != nil {
		t.Fatalf("unexpected error with RequireAuthenticDocument unset: %s", err)
	}
}

func TestRequireAuthenticDocumentChipRejectsAuth(t *testing.T) {
	// ISO 7816-4 error status words an (emulated) chip may answer AA INTERNAL AUTHENTICATE
	// or CA MSE:Set AT with (see #525).
	statusWords := []string{"6300", "6700", "6800", "6900", "6982", "6A00", "6A80", "6A88", "6B00", "6C00", "6E00", "6F00", "6FFF"}

	protocols := []struct {
		name  string
		strip func(doc *document.Document)
	}{
		{"AA", func(doc *document.Document) { doc.Mf.Lds1.Dg14 = nil }},
		{"CA", func(doc *document.Document) { doc.Mf.Lds1.Dg15 = nil }},
		{"AA+CA", func(_ *document.Document) {}},
	}

	for _, p := range protocols {
		for _, sw := range statusWords {
			t.Run(p.name+"/"+sw, func(t *testing.T) {
				reader := requireAuthenticReader(t, &iso7816.StaticTransceiver{RApdu: utils.HexToBytes(sw)})
				state := trustedState(t)

				doc, err := document.SampleDocument()
				if err != nil {
					t.Fatalf("SampleDocument error: %s", err)
				}
				p.strip(doc)
				state.docEx.Document = *doc

				if err := performChipAuthentication(reader, state); err != nil {
					t.Fatalf("unexpected performChipAuthentication error: %s", err)
				}

				err = checkAuthenticDocument(reader, state)
				if !errors.Is(err, ErrDocumentNotAuthentic) {
					t.Fatalf("expected ErrDocumentNotAuthentic, got: %v", err)
				}
				session := state.docEx.Session
				for _, protoErr := range []error{session.ActiveAuthErr, session.ChipAuthErr} {
					if protoErr != nil && !errors.Is(err, protoErr) {
						t.Fatalf("error does not wrap protocol error %q: %s", protoErr, err)
					}
				}
			})
		}
	}
}

func TestCheckAuthenticDocument(t *testing.T) {
	aaErr := errors.New("AA failed")
	caErr := errors.New("CA failed")
	paceErr := errors.New("PACE-CAM failed")
	paErr := errors.New("PA failed")
	verifyErr := errors.New("Document.Verify failed")

	testCases := []struct {
		name    string
		setup   func(s *document.Session)
		wantErr []error // nil: expect success
	}{
		{
			name:  "no chip authentication offered",
			setup: func(_ *document.Session) {},
		},
		{
			name: "AA succeeds",
			setup: func(s *document.Session) {
				s.ActiveAuthResult = &document.ActiveAuthResult{Success: true}
			},
		},
		{
			name: "AA fails but CA succeeds",
			setup: func(s *document.Session) {
				s.ActiveAuthResult, s.ActiveAuthErr = &document.ActiveAuthResult{Success: false}, aaErr
				s.ChipAuthResult = &document.ChipAuthResult{Success: true}
			},
		},
		{
			name: "PACE-CAM succeeds but AA fails",
			setup: func(s *document.Session) {
				s.PaceCamResult = &document.PaceCamResult{Success: true}
				s.ActiveAuthResult, s.ActiveAuthErr = &document.ActiveAuthResult{Success: false}, aaErr
			},
		},
		{
			name: "AA fails",
			setup: func(s *document.Session) {
				s.ActiveAuthResult, s.ActiveAuthErr = &document.ActiveAuthResult{Success: false}, aaErr
			},
			wantErr: []error{ErrDocumentNotAuthentic, aaErr},
		},
		{
			name: "AA and CA fail",
			setup: func(s *document.Session) {
				s.ActiveAuthResult, s.ActiveAuthErr = &document.ActiveAuthResult{Success: false}, aaErr
				s.ChipAuthResult, s.ChipAuthErr = &document.ChipAuthResult{Success: false}, caErr
			},
			wantErr: []error{ErrDocumentNotAuthentic, aaErr, caErr},
		},
		{
			name: "AA unsuccessful without error",
			setup: func(s *document.Session) {
				s.ActiveAuthResult = &document.ActiveAuthResult{Success: false}
			},
			wantErr: []error{ErrDocumentNotAuthentic},
		},
		{
			name: "PACE-CAM succeeds but CardSecurity not verified",
			setup: func(s *document.Session) {
				s.PassiveAuthResult.CardSec = nil
				s.PaceCamResult = &document.PaceCamResult{Success: true}
			},
			wantErr: []error{ErrDocumentNotAuthentic},
		},
		{
			name: "PACE-CAM error under BAC fallback",
			setup: func(s *document.Session) {
				s.PaceResult = &document.PaceResult{Oid: oid.OidPaceEcdhCamAesCbcCmac128}
				s.PaceErr = paceErr
			},
			wantErr: []error{ErrDocumentNotAuthentic, paceErr},
		},
		{
			name: "PACE-GM error is not a chip authentication attempt",
			setup: func(s *document.Session) {
				s.PaceResult = &document.PaceResult{Oid: oid.OidPaceEcdhGmAesCbcCmac128}
				s.PaceErr = paceErr
			},
		},
		{
			name: "PACE unsupported locally is not a chip authentication attempt",
			setup: func(s *document.Session) {
				s.PaceResult = &document.PaceResult{}
				s.PaceErr = fmt.Errorf("selectPaceConfig: %w", pace.ErrPACEUnsupportedLocally)
			},
		},
		{
			name: "passive authentication fails",
			setup: func(s *document.Session) {
				s.PassiveAuthResult, s.PassiveAuthErr = &document.PassiveAuthResult{Success: false}, paErr
				s.ActiveAuthResult = &document.ActiveAuthResult{Success: true}
			},
			wantErr: []error{ErrDocumentNotAuthentic, paErr},
		},
		{
			name: "passive authentication not performed",
			setup: func(s *document.Session) {
				s.PassiveAuthResult = nil
			},
			wantErr: []error{ErrDocumentNotAuthentic},
		},
		{
			name: "Document.Verify fails",
			setup: func(s *document.Session) {
				s.DocumentVerifyErr = verifyErr
			},
			wantErr: []error{ErrDocumentNotAuthentic, verifyErr},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reader := requireAuthenticReader(t, &PanicTransceiver{P: "no APDUs expected"})
			state := trustedState(t)
			tc.setup(&state.docEx.Session)

			err := checkAuthenticDocument(reader, state)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				return
			}
			for _, want := range tc.wantErr {
				if !errors.Is(err, want) {
					t.Fatalf("expected error wrapping %q, got: %v", want, err)
				}
			}
		})
	}
}

// TestRequireAuthenticDocumentRealVerification runs the real Document.Verify and Passive
// Authentication steps before the check, rather than assuming a Passive Authentication result.
func TestRequireAuthenticDocumentRealVerification(t *testing.T) {
	ukData, err := os.ReadFile("../verifier/testdata/GBR-099250692.gmrtd")
	if err != nil {
		t.Fatalf("ReadFile error: %s", err)
	}

	masterList, err := cms.DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList error: %s", err)
	}

	// the UK CSCA expired on 2026-07-24 and has since been dropped from the master lists
	var ukCsca cms.GenericCertPool
	if err := ukCsca.Add(utils.HexToBytes("308205FA308203E2A0030201020204492EAE16300D06092A864886F70D01010B05003041310B3009060355040613026762310E300C060355040A1305554B4B50413122302006035504031319436F756E747279205369676E696E6720417574686F72697479301E170D3130303332343134303230315A170D3236303732343134333230315A3041310B3009060355040613026762310E300C060355040A1305554B4B50413122302006035504031319436F756E747279205369676E696E6720417574686F7269747930820222300D06092A864886F70D01010105000382020F003082020A0282020100C3583682D60EE9DB5E77F3CD27F02C8657ABA30C70A21EBC33FCAFA8E96B5806A090EF29CDC8A4A286F750C4F237CE89A207D460DED39854CFF2BA8F4E7807C655FE1B60E7459FF7E24DE2806EA6823BA8B3DD0A00C80B3DCB8BAE3C4620D9F5A81E3144E7805C96F147AFB13D6C9BAAB3D469EFCA9EADACAD81ED623FCCA82263D72350F553C17DE29352F937CA3EEFDAA902FE718EFC5F90CE9B35027E5F56CD92FDE396B2ACD2C8A83A7F5712CF7DF298607D072B8E82C5DD94BE323D293ADBD25B4F53467AAAE53E92BDD23E26B5501DA24B53E1F492917CA0FA8C59680FB17C952AC642944639B385A06315C251B204DD922E2F86A1D40F1FE3626E602D8D9ED0870C5D0E86ACB0E3845557E63CBB327D9EFFECD317A31FA337AEAC6F9304EB59B63DFEA4D7EC7AC94891D5D8B14F4FB4DB1AA4A88AD5B339FE7DCB460F8231F5B0628A6EA75C3FC252BF00C0D54D850D489346F3753A476A0EA237CAF9001CE729BB2EC2CEA6368F040A2B1B1108A2133EFFE4CA369D043D58A72D0AC1202138CCA1A370B26D576DA079DBDD6C59989F1E40F670AF27E28231ED3F7A5C7F1F699B9AB217F7125993CDA5C0B25147A0C37D08098B85D8B4F231303B1DF92EFAF03E31D92DE00D6971FD4D43971C318DCCB3F1FE908520F5AA788EADE562D0B23F85FF76340C5D181811B2C19529387807EBDD7C5AB09D971F0D3AB516AD0203010001A381F93081F6300E0603551D0F0101FF04040302010630120603551D130101FF040830060101FF02010030630603551D1F045C305A3058A056A054A4523050310B3009060355040613026762310E300C060355040A1305554B4B50413122302006035504031319436F756E747279205369676E696E6720417574686F72697479310D300B0603550403130443524C31302B0603551D1004243022800F32303130303332343134303230315A810F32303236303732343134333230315A301F0603551D230418301680144531A5B73BCF8BB27C7FAC88C74B4505F6C936B3301D0603551D0E041604144531A5B73BCF8BB27C7FAC88C74B4505F6C936B3300D06092A864886F70D01010B0500038202010054F23F6A723698B06338E7A37FB2C740506E2175970C76E20D629D0AB5557359360826E7A611B3748470C1E7995952547C1BB790F4899D258F9127F6C4730F5FF63A8498EAEB50FAF767283B73325B968B497E8C6361073EC25DA7E4C225F36E5870D5874F11BC102F4DC2FEE784F3B3CB9AF3BD3C55F5A72C1883EB2632153B16F594AA086D549228CF0013199D66899181BE47AC0EF37D5F4FE7CB23B8565CD7F4099968DD90791E8EAAE871914BB25C4ABC5556D8387D4964CD87051088431FC32AAC31E37DCEE14BA835C9618E1365216BD227563D99520FD03B101CA7EABFE326BA71B4DE40DA328B2F65E99B591B01FC132C9713BF525238FEDE68A509653C196AA73404D970509D7112EFBC62F385F9642DDE0FBFC7228E0AB388C69E0304B617CC56E4B6253FBD005B22AFF67420F51069AE8D2DC9E5F076E33016AA4E1BBE11A3B79CBA4E41002021639126B7DDC79DC6DF2CD2C1DDB706B825125514F8E5797C409B1B69A8EADA1E95E1FAD139F7C1E189008A5BAB74DF7E87830AF1FBDFC27BD1985CF8DFE5C631AA4F7C0D439D80FB35B34F7722FC0EFBD2B88B4C4BC918EE4E5BD868EB49E1B6858696B364BCEC7D69E494E7DA8198D69A6ABE1F31D01502F5E78550808C2F14CD447E0E56ACDF01A5A145C52EC867232091F1C71800654CC7529557C3414667F9711275B36E92196DD8D600587D4E93FD08D3")); err != nil {
		t.Fatalf("ukCsca.Add error: %s", err)
	}
	masterList.AddCertPool(&ukCsca)

	ukDocument := func(t *testing.T) *document.Document {
		doc, _, err := document.UnmarshalVerifiableDoc(ukData)
		if err != nil {
			t.Fatalf("UnmarshalVerifiableDoc error: %s", err)
		}
		return doc
	}

	sampleDocument := func(t *testing.T) *document.Document {
		doc, err := document.SampleDocument()
		if err != nil {
			t.Fatalf("SampleDocument error: %s", err)
		}
		return doc
	}

	aaErr := errors.New("AA failed")

	testCases := []struct {
		name    string
		doc     func(t *testing.T) *document.Document
		session func(s *document.Session)
		wantErr []error // nil: expect success

		wantDataTrusted bool
	}{
		{
			// trusted data, and the document offers no AA/CA/PACE-CAM
			name:    "UK passport",
			doc:     ukDocument,
			session: func(_ *document.Session) {},

			wantDataTrusted: true,
		},
		{
			name: "UK passport with failed chip authentication",
			doc:  ukDocument,
			session: func(s *document.Session) {
				s.ActiveAuthResult, s.ActiveAuthErr = &document.ActiveAuthResult{Success: false}, aaErr
			},
			wantErr: []error{ErrDocumentNotAuthentic, aaErr},

			wantDataTrusted: true,
		},
		{
			// its data groups come from different ICAO worked examples, so Passive Authentication fails
			name:    "synthetic sample document",
			doc:     sampleDocument,
			session: func(_ *document.Session) {},
			wantErr: []error{ErrDocumentNotAuthentic},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var status MockStatus
			reader := NewReader(&status, iso7816.NewNfcSession(&PanicTransceiver{P: "no APDUs expected"}), masterList)
			reader.RequireAuthenticDocument()

			state := NewReaderState(nil, nil, password.NewPasswordNil())
			state.docEx.Document = *tc.doc(t)
			tc.session(&state.docEx.Session)

			err := runSteps(reader, state, verifyDocument, performPassiveAuthentication, checkAuthenticDocument)

			if got := state.docEx.Summary().DataTrusted; got != tc.wantDataTrusted {
				t.Fatalf("DataTrusted = %v, want %v (PassiveAuthErr: %v, DocumentVerifyErr: %v)",
					got, tc.wantDataTrusted, state.docEx.Session.PassiveAuthErr, state.docEx.Session.DocumentVerifyErr)
			}
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				return
			}
			for _, want := range tc.wantErr {
				if !errors.Is(err, want) {
					t.Fatalf("expected error wrapping %q, got: %v", want, err)
				}
			}
		})
	}
}
