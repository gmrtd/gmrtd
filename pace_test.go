package gmrtd

import (
	"bytes"
	"crypto/elliptic"
	"math/big"
	"reflect"
	"testing"

	"github.com/ebfe/brainpool"
)

func TestDecryptNonce(t *testing.T) {

	pace := paceConfigGetByOID(id_PACE_ECDH_GM_AES_CBC_CMAC_128)
	encryptedNonce := HexToBytes("95A3A016522EE98D01E76CB6B98B42C3")
	kKdf := HexToBytes("89DED1B26624EC1E634C1989302849DD")

	decryptedNonce := pace.decryptNonce(kKdf, encryptedNonce)

	decryptedNonceExp := HexToBytes("3F00C4D39D153F2B2A214A078D899B22")

	if !bytes.Equal(decryptedNonce, decryptedNonceExp) {
		t.Errorf("Nonce decryption failed")
	}
}

func TestDoECDH(t *testing.T) {
	domainParams := getStandardisedDomainParams(13) // 0x0D

	var termPri *big.Int
	var termPub EC_POINT

	termPri, _ = new(big.Int).SetString("7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99", 16)
	termPub.x, _ = new(big.Int).SetString("7ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E", 16)
	termPub.y, _ = new(big.Int).SetString("544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D", 16)

	var chipPri *big.Int
	var chipPub EC_POINT

	chipPri, _ = new(big.Int).SetString("498FF49756F2DC1587840041839A85982BE7761D14715FB091EFA7BCE9058560", 16)
	chipPub.x, _ = new(big.Int).SetString("824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57", 16)
	chipPub.y, _ = new(big.Int).SetString("30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54", 16)

	expSharedSecretX := HexToBytes("60332EF2450B5D247EF6D3868397D398852ED6E8CAF6FFEEF6BF85CA57057FD5")
	expSharedSecretY := HexToBytes("0840CA7415BAF3E43BD414D35AA4608B93A2CAF3A4E3EA4E82C9C13D03EB7181")

	{
		shared := doECDH(termPri.Bytes(), &chipPub, domainParams.ec)

		if !bytes.Equal(expSharedSecretX, shared.x.Bytes()) || !bytes.Equal(expSharedSecretY, shared.y.Bytes()) {
			t.Errorf("ECDH error")
		}
	}

	{
		shared := doECDH(chipPri.Bytes(), &termPub, domainParams.ec)

		if !bytes.Equal(expSharedSecretX, shared.x.Bytes()) || !bytes.Equal(expSharedSecretY, shared.y.Bytes()) {
			t.Errorf("ECDH error")
		}
	}
}

func TestDoGenericMappingEC(t *testing.T) {
	domainParams := getStandardisedDomainParams(13) // 0x0D

	s := HexToBytes("3F00C4D39D153F2B2A214A078D899B22")

	var termShared EC_POINT

	termShared.x, _ = new(big.Int).SetString("60332EF2450B5D247EF6D3868397D398852ED6E8CAF6FFEEF6BF85CA57057FD5", 16)
	termShared.y, _ = new(big.Int).SetString("0840CA7415BAF3E43BD414D35AA4608B93A2CAF3A4E3EA4E82C9C13D03EB7181", 16)

	var mappedG *EC_POINT = doGenericMappingEC(s, &termShared, domainParams.ec)

	expMappedGx := HexToBytes("8CED63C91426D4F0EB1435E7CB1D74A46723A0AF21C89634F65A9AE87A9265E2")
	expMappedGy := HexToBytes("8C879506743F8611AC33645C5B985C80B5F09A0B83407C1B6A4D857AE76FE522")

	if !bytes.Equal(expMappedGx, mappedG.x.Bytes()) || !bytes.Equal(expMappedGy, mappedG.y.Bytes()) {
		t.Errorf("Generic Mapping (EC) error")
	}
}

func TestBuild7F49(t *testing.T) {
	domainParams := getStandardisedDomainParams(13) // 0x0D

	var termPub EC_POINT

	termPub.x, _ = new(big.Int).SetString("2DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C", 16)
	termPub.y, _ = new(big.Int).SetString("3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462", 16)

	var chipPub EC_POINT

	chipPub.x, _ = new(big.Int).SetString("9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB", 16)
	chipPub.y, _ = new(big.Int).SetString("7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094", 16)

	rawOID := []byte{0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02}

	tifdData := build_7F49(rawOID, EncodeX962EcPoint(domainParams.ec, &chipPub))
	ticData := build_7F49(rawOID, EncodeX962EcPoint(domainParams.ec, &termPub))

	expTifdData := HexToBytes("7F494F060A04007F000702020402028641049E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094")
	if !bytes.Equal(expTifdData, tifdData) {
		t.Errorf("Incorrect tifd-data\n[Exp] %x\n[Act] %x", expTifdData, tifdData)
	}

	expTicData := HexToBytes("7F494F060A04007F000702020402028641042DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462")
	if !bytes.Equal(expTicData, ticData) {
		t.Errorf("Incorrect tic-data\n[Exp] %x\n[Act] %x", expTicData, ticData)
	}

}

func TestSelectPaceForConfig(t *testing.T) {
	// NB card-access file has 2 entries.. we test with both in different orders to verify priority based selection
	var cardAccess1 *CardAccess = NewCardAccess(HexToBytes("31283012060a04007f000702020402040201020201103012060a04007f00070202040604020102020110"))
	var cardAccess2 *CardAccess = NewCardAccess(HexToBytes("31283012060a04007f000702020406040201020201103012060a04007f00070202040204020102020110"))

	// TODO - verify other params... move to table based test?... include single entry test

	paceConfig1, domainParams1 := selectPaceConfig(cardAccess1)

	if paceConfig1.oid != "0.4.0.127.0.7.2.2.4.6.4" {
		t.Errorf("Invalid PACE OID (1) (%s)", paceConfig1.oid)
	}

	if (domainParams1.isECDH != true) || (domainParams1.ec != brainpool.P384r1()) {
		t.Errorf("Invaid domain-params (1)")
	}

	paceConfig2, domainParams2 := selectPaceConfig(cardAccess2)

	if paceConfig2.oid != "0.4.0.127.0.7.2.2.4.6.4" {
		t.Errorf("Invalid PACE OID (2) (%s)", paceConfig2.oid)
	}

	if (domainParams2.isECDH != true) || (domainParams2.ec != brainpool.P384r1()) {
		t.Errorf("Invaid domain-params (2)")
	}
}

// PACE test for GM (ECDH) based on worked example in ICAO9303 p11 specs (Appendix G1)
func TestDoPace_GM_ECDH(t *testing.T) {
	var nfc *NfcSession

	{
		var transceiver *MockTransceiver = new(MockTransceiver)

		// add in expected request/response tuples
		transceiver.AddReqRsp("0022C1A40F800A04007F00070202040202830101", "9000")
		transceiver.AddReqRsp("10860000027C0000", "7C12801095A3A016522EE98D01E76CB6B98B42C39000")
		transceiver.AddReqRsp("10860000457C438141047ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D00", "7C43824104824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F5730D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C549000")
		transceiver.AddReqRsp("10860000457C438341042DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB3646200", "7C438441049E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F0949000")
		transceiver.AddReqRsp("008600000C7C0A8508C2B0BD78D94BA86600", "7C0A86083ABB9674BCE93C089000")

		nfc = NewNfcSession(transceiver)
	}

	// setup static EC keys for test
	getTestKeyGenEc := func() func(ec elliptic.Curve) ([]byte, *EC_POINT) {
		var idx int

		return func(ec elliptic.Curve) (pri []byte, pub *EC_POINT) {
			var tmpPri *big.Int
			var tmpPub EC_POINT

			switch idx {
			case 0:
				tmpPri, _ = new(big.Int).SetString("7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99", 16)
				tmpPub.x, _ = new(big.Int).SetString("7ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E", 16)
				tmpPub.y, _ = new(big.Int).SetString("544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D", 16)
			case 1:
				tmpPri, _ = new(big.Int).SetString("A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595", 16)
				// NB set public-key to dummy value as it should be manually calculated using the mapped generator (Gx/y)
				//    - this way we can test that Gxy is getting propagated from earlier step and flow is working correcvtly
				tmpPub.x = big.NewInt(0)
				tmpPub.y = big.NewInt(0)
			default:
				t.Errorf("Invalid key-gen index (idx:%1d)", idx)
			}

			idx++

			return tmpPri.Bytes(), &tmpPub
		}
	}

	var doc Document

	// PACEInfo: 3012060A 04007F00 07020204 02020201 0202010D
	//				** NB added 3114 to start
	doc.CardAccess = NewCardAccess(HexToBytes("31143012060A04007F0007020204020202010202010D"))

	// password (MRZ)
	var password *Password = NewPasswordMrzi("T22000129", "640812", "101031")

	var pace *Pace = NewPace()

	// override EC key-generator (to ensure predictable keys)
	pace.keyGeneratorEc = getTestKeyGenEc()

	pace.DoPACE(nfc, password, &doc)

	// verify Secure-Messaging was setup correctly
	{
		smExp := NewSecureMessaging(AES, HexToBytes("F5F0E35C0D7161EE6724EE513A0D9A7F"), HexToBytes("FE251C7858B356B24514B3BD5F4297D1"))

		if !reflect.DeepEqual(smExp, nfc.sm) {
			t.Errorf("SecureMessaging differs to expected")
		}
	}

	// verify chip-auth-status is NA
	if doc.chipAuthStatus != CHIP_AUTH_STATUS_NA {
		t.Errorf("ChipAuthStatus is not reflecting NA")
	}

}

// PACE test for CAM (ECDH) based on worked example in ICAO9303 p11 specs (Appendix I)
func TestDoPace_CAM_ECDH(t *testing.T) {
	var nfc *NfcSession

	{
		var transceiver *MockTransceiver = new(MockTransceiver)

		// add in expected request/response tuples
		transceiver.AddReqRsp("0022C1A40F800A04007F00070202040602830101", "9000")
		transceiver.AddReqRsp("10860000027C0000", "7C128010CB60E8E0D85B76A9BD304747C2AD42E29000")
		transceiver.AddReqRsp("10860000457C438141047F1D410ADB7DDB3B84BF1030800981A9105D7457B4A3ADE002384F3086C67EDE1AB889104A27DB6D842B019020FBF3CEACB0DC627F7BDCAC29969E19D0E553C100", "7C43824104A234236AA9B9621E8EFB73B5245C0E09D2576E5277183C1208BDD55280CAE8B304F365713A356E65A451E165ECC9AC0AC46E3771342C8FE5AEDD092685338E239000")
		transceiver.AddReqRsp("10860000457C43834104446C934084D9DAB863944F219520076C29EE3F7AE6722B11FF319EC1C7728F955483400BFF60BF0C5929270009277DC2A515E12575010AD9BA916CF1BF86FEFC00", "7C4384410402AD566F3C6EC7F9324509AD50A51FA52030782A4968FCFEDF737DAEA993333111C3B9B4C2287789BD137E7F8AA882E2A3C633CCD6ECC2C63C57AD401A09C2E19000")
		transceiver.AddReqRsp("008600000C7C0A8508E86BD06018A1CD3B00", "7C3C86088596CF055C67C1A38A301EEA964DAAE372AC990E3EFDE6333353BFC89A6704D93DA8798CF77F5B7A54BD10CBA372B42BE0B9B5F28AA8DE2F4F929000")
		// CardSecurity file
		// NB manually encoded based on the Secure Messaging settings
		transceiver.AddReqRsp("0ca4020c1d8711013824f3cb16caa40ddff8459c215cc4988e08158449671fcc718300", "990290008E085e007ca87260a77f9000")
		transceiver.AddReqRsp("0cb000000d9701048e081049244eed15563d00", "8711017B0085CFF0A3845B7F1B02E72BBE6395990290008E083cf26fad48f7888b9000")
		transceiver.AddReqRsp("0cb000040d9701628e08d3fb753d695a16fe00", "877101E7E1E51C85C8F09209C59CA459305EC2CC23FD0E6938F3915F74CAAC06794A8518FEB0A11CD8A7C0A26B88F3DA567A803DBDD79AA853FE272A9C02690017EC95CDCDB0FEB944E1B63FC8F293552F32B663B16E929871E785D164B72DF076B89C480537A5B4B80EAAAAF5E786D89A3814990290008E080cbfd5f7f43cc3619000")

		nfc = NewNfcSession(transceiver)
	}

	// setup static EC keys for test
	getTestKeyGenEc := func() func(ec elliptic.Curve) ([]byte, *EC_POINT) {
		var idx int

		return func(ec elliptic.Curve) (pri []byte, pub *EC_POINT) {
			var tmpPri *big.Int
			var tmpPub EC_POINT

			switch idx {
			case 0:
				tmpPri, _ = new(big.Int).SetString("5D8BB87BD74D985A4B7D4325B9F7B976FE835122773400798914AA22738135CC", 16)
				tmpPub.x, _ = new(big.Int).SetString("7F1D410ADB7DDB3B84BF1030800981A9105D7457B4A3ADE002384F3086C67EDE", 16)
				tmpPub.y, _ = new(big.Int).SetString("1AB889104A27DB6D842B019020FBF3CEACB0DC627F7BDCAC29969E19D0E553C1", 16)
			case 1:
				tmpPri, _ = new(big.Int).SetString("76ECFDAA9841C323A3F5FC5E88B88DB3EFF7E35EBF57A7E6946CB630006C2120", 16)
				// NB set public-key to dummy value as it should be manually calculated using the mapped generator (Gx/y)
				//    - this way we can test that Gxy is getting propagated from earlier step and flow is working correcvtly
				tmpPub.x = big.NewInt(0)
				tmpPub.y = big.NewInt(0)
			default:
				t.Errorf("Invalid key-gen index (idx:%1d)", idx)
			}

			idx++

			return tmpPri.Bytes(), &tmpPub
		}
	}

	var doc Document

	// PACEInfo: 3012060A04007F0007020204060202010202010D
	//				** NB added 3114 to start
	doc.CardAccess = NewCardAccess(HexToBytes("31143012060A04007F0007020204060202010202010D"))

	// password (MRZ)
	var password *Password = NewPasswordMrzi("C11T002JM", "960812", "231031")

	var pace *Pace = NewPace()

	// override EC key-generator (to ensure predictable keys)
	pace.keyGeneratorEc = getTestKeyGenEc()

	pace.DoPACE(nfc, password, &doc)

	// verify Secure-Messaging state (inc final SSC) is correct
	{
		sm_exp := NewSecureMessaging(AES, HexToBytes("0A9DA4DB03BDDE39FC5202BC44B2E89E"), HexToBytes("4B1C06491ED5140CA2B537D344C6C0B1"))
		sm_exp.SetSSC(HexToBytes("00000000000000000000000000000006"))

		if !reflect.DeepEqual(sm_exp, nfc.sm) {
			t.Errorf("SecureMessaging differs to expected")
		}
	}

	// verify chip-auth-status reflects PACE-CAM was performed
	if doc.chipAuthStatus != CHIP_AUTH_STATUS_PACE_CAM {
		t.Errorf("ChipAuthStatus is not reflecting PACE-CAM")
	}
}
