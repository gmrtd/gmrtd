package pace

import (
	"bytes"
	"crypto/elliptic"
	"encoding/asn1"
	"math"
	"math/big"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/password"
	"github.com/gmrtd/gmrtd/utils"
	"github.com/osanderson/brainpool"
)

func TestPaceConfigGetByOID(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	// NB error as we're using an invalid OID
	_ = paceConfigGetByOID(oid.OidBsiDe)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestGetStandardisedDomainParams(t *testing.T) {
	testCases := []struct {
		paramId int
		bitSize int
	}{
		{
			paramId: 9,
			bitSize: 192,
		},
		{
			paramId: 10,
			bitSize: 224,
		},
		{
			paramId: 11,
			bitSize: 224,
		},
		{
			paramId: 12,
			bitSize: 256,
		},
		{
			paramId: 13,
			bitSize: 256,
		},
		{
			paramId: 14,
			bitSize: 320,
		},
		{
			paramId: 15,
			bitSize: 384,
		},
		{
			paramId: 16,
			bitSize: 384,
		},
		{
			paramId: 17,
			bitSize: 512,
		},
		{
			paramId: 18,
			bitSize: 521,
		},
	}
	for _, tc := range testCases {
		var domainParams *PACEDomainParams = getStandardisedDomainParams(tc.paramId)

		if !domainParams.isECDH {
			t.Errorf("Should be ECDH")
		}

		if domainParams.ec.Params().BitSize != tc.bitSize {
			t.Errorf("Incorrect BitSize (ParamId:%d, Exp:%d, Act%d:)", tc.paramId, tc.bitSize, domainParams.ec.Params().BitSize)
		}

		// verify that we can generate a keypair
		var ecKeypair cryptoutils.EcKeypair = cryptoutils.KeyGeneratorEc(domainParams.ec)

		/*
		* sanity check that the public key doesn't exceed the bit-size
		 */
		maxBytes := int(math.Ceil(float64(tc.bitSize) / 8))

		xBytes := len(ecKeypair.Pub.X.Bytes())
		yBytes := len(ecKeypair.Pub.Y.Bytes())

		if (xBytes > maxBytes) || (yBytes > maxBytes) {
			t.Errorf("Incorrect public key size: exp(max):%1d, actX:%1d, actY:%1d signX:%1d signY:%1d", maxBytes, xBytes, yBytes, ecKeypair.Pub.X.Sign(), ecKeypair.Pub.Y.Sign())
		}
	}
}

func TestGetStandardisedDomainParamsErr(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	// NB error as we're using an invalid paramId
	_ = getStandardisedDomainParams(-1)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestDecryptNonce(t *testing.T) {

	pace := paceConfigGetByOID(oid.OidPaceEcdhGmAesCbcCmac128)
	encryptedNonce := utils.HexToBytes("95A3A016522EE98D01E76CB6B98B42C3")
	kKdf := utils.HexToBytes("89DED1B26624EC1E634C1989302849DD")

	decryptedNonce := pace.decryptNonce(kKdf, encryptedNonce)

	decryptedNonceExp := utils.HexToBytes("3F00C4D39D153F2B2A214A078D899B22")

	if !bytes.Equal(decryptedNonce, decryptedNonceExp) {
		t.Errorf("Nonce decryption failed")
	}
}

func TestDecryptNonceKeyLengthErr(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	pace := paceConfigGetByOID(oid.OidPaceEcdhGmAesCbcCmac128)
	encryptedNonce := utils.HexToBytes("95A3A016522EE98D01E76CB6B98B42C3")
	kKdf := utils.HexToBytes("89DED1B26624EC1E634C1989302849DD00") // 1 byte too long

	_ = pace.decryptNonce(kKdf, encryptedNonce)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}

func TestComputeAuthTokenCbcAesErr(t *testing.T) {
	// Test that error occurs when CBC is used with AES (i.e. !TDES)

	// start with a valid pace-config
	var paceConfig PaceConfig = PaceConfig{oid.OidPaceDhGm3DesCbcCbc, GM, cryptoutils.TDES, 112, CBC, 200}

	// modify to have an invalid cipher
	paceConfig.cipher = cryptoutils.AES

	var key []byte = utils.HexToBytes("AB94FDECF2674FDFB9B391F85D7F76F2")
	var data []byte = utils.HexToBytes("0000000000000000000000000000000000000000000000000000000000000000")

	_, err := paceConfig.computeAuthToken(key, data)

	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestComputeAuthTokenCbcTDesKeyErr(t *testing.T) {
	// Test that error occurs when CBC/TDES key has incorrect length

	// start with a valid pace-config
	var paceConfig PaceConfig = PaceConfig{oid.OidPaceDhGm3DesCbcCbc, GM, cryptoutils.TDES, 112, CBC, 200}

	var key []byte = utils.HexToBytes("AB94FDECF2674FDFB9B391F85D7F76F200") // 1 extra byte
	var data []byte = utils.HexToBytes("0000000000000000000000000000000000000000000000000000000000000000")

	_, err := paceConfig.computeAuthToken(key, data)

	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestComputeAuthTokenCmacTDesErr(t *testing.T) {
	// Test that error occurs when CMAC is used with TDES (i.e. !AES)

	// start with a valid pace-config
	var paceConfig PaceConfig = PaceConfig{oid.OidPaceDhGmAesCbcCmac256, GM, cryptoutils.AES, 256, CMAC, 203}

	// modify to have an invalid cipher
	paceConfig.cipher = cryptoutils.TDES

	var key []byte = utils.HexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	var data []byte = utils.HexToBytes("0000000000000000000000000000000000000000000000000000000000000000")

	_, err := paceConfig.computeAuthToken(key, data)

	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestComputeAuthTokenCmacAesKeyErr(t *testing.T) {
	// Test that error occurs when CMAC/AES key has incorrect length

	// start with a valid pace-config
	var paceConfig PaceConfig = PaceConfig{oid.OidPaceDhGmAesCbcCmac256, GM, cryptoutils.AES, 256, CMAC, 203}

	var key []byte = utils.HexToBytes("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F00") // 1 extra byte
	var data []byte = utils.HexToBytes("0000000000000000000000000000000000000000000000000000000000000000")

	_, err := paceConfig.computeAuthToken(key, data)

	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestComputeAuthTokenATErr(t *testing.T) {
	// Test that error occurs when an unknown Auth-Token type is specified (not CBC/CMAC)

	// start with a valid pace-config
	var paceConfig PaceConfig = PaceConfig{oid.OidPaceDhGm3DesCbcCbc, GM, cryptoutils.TDES, 112, CBC, 200}

	// modify to have an invalid auth-token
	paceConfig.authToken = 255 // invalid

	var key []byte = utils.HexToBytes("AB94FDECF2674FDFB9B391F85D7F76F2")
	var data []byte = utils.HexToBytes("0000000000000000000000000000000000000000000000000000000000000000")

	_, err := paceConfig.computeAuthToken(key, data)

	if err == nil {
		t.Errorf("Expected error")
	}
}

func TestDoGenericMappingEC(t *testing.T) {
	domainParams := getStandardisedDomainParams(13) // 0x0D

	s := utils.HexToBytes("3F00C4D39D153F2B2A214A078D899B22")

	var termShared cryptoutils.EcPoint

	termShared.X, _ = new(big.Int).SetString("60332EF2450B5D247EF6D3868397D398852ED6E8CAF6FFEEF6BF85CA57057FD5", 16)
	termShared.Y, _ = new(big.Int).SetString("0840CA7415BAF3E43BD414D35AA4608B93A2CAF3A4E3EA4E82C9C13D03EB7181", 16)

	var mappedG *cryptoutils.EcPoint = doGenericMappingEC(s, &termShared, domainParams.ec)

	var expMappedG cryptoutils.EcPoint
	expMappedG.X, _ = new(big.Int).SetString("8CED63C91426D4F0EB1435E7CB1D74A46723A0AF21C89634F65A9AE87A9265E2", 16)
	expMappedG.Y, _ = new(big.Int).SetString("8C879506743F8611AC33645C5B985C80B5F09A0B83407C1B6A4D857AE76FE522", 16)

	if !expMappedG.Equal(*mappedG) {
		t.Errorf("Generic Mapping (EC) error")
	}
}

func TestBuild7F49(t *testing.T) {
	domainParams := getStandardisedDomainParams(13) // 0x0D

	var termPub cryptoutils.EcPoint

	termPub.X, _ = new(big.Int).SetString("2DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C", 16)
	termPub.Y, _ = new(big.Int).SetString("3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462", 16)

	var chipPub cryptoutils.EcPoint

	chipPub.X, _ = new(big.Int).SetString("9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB", 16)
	chipPub.Y, _ = new(big.Int).SetString("7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094", 16)

	rawOID := []byte{0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02}

	tifdData := encodePubicKeyTemplate7F49(rawOID, cryptoutils.EncodeX962EcPoint(domainParams.ec, &chipPub))
	ticData := encodePubicKeyTemplate7F49(rawOID, cryptoutils.EncodeX962EcPoint(domainParams.ec, &termPub))

	expTifdData := utils.HexToBytes("7F494F060A04007F000702020402028641049E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094")
	if !bytes.Equal(expTifdData, tifdData) {
		t.Errorf("Incorrect tifd-data\n[Exp] %x\n[Act] %x", expTifdData, tifdData)
	}

	expTicData := utils.HexToBytes("7F494F060A04007F000702020402028641042DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462")
	if !bytes.Equal(expTicData, ticData) {
		t.Errorf("Incorrect tic-data\n[Exp] %x\n[Act] %x", expTicData, ticData)
	}

}

func TestSelectPaceForConfig(t *testing.T) {
	// NB card-access file has 2 entries.. we test with both in different orders to verify priority based selection
	testCases := []struct {
		cardAccessBytes []byte
		expOid          asn1.ObjectIdentifier
		expIsEcdh       bool
		expEc           elliptic.Curve
	}{
		{
			cardAccessBytes: utils.HexToBytes("31283012060a04007f000702020402040201020201103012060a04007f00070202040604020102020110"),
			expOid:          oid.OidPaceEcdhCamAesCbcCmac256,
			expIsEcdh:       true,
			expEc:           brainpool.P384r1(),
		},
		{
			cardAccessBytes: utils.HexToBytes("31283012060a04007f000702020406040201020201103012060a04007f00070202040204020102020110"),
			expOid:          oid.OidPaceEcdhCamAesCbcCmac256,
			expIsEcdh:       true,
			expEc:           brainpool.P384r1(),
		},
	}
	for _, tc := range testCases {
		var err error

		var cardAccess *document.CardAccess
		cardAccess, err = document.NewCardAccess(tc.cardAccessBytes)
		if err != nil {
			t.Errorf("Unexpected NewCardAccess() error: %s", err)
		}

		paceConfig, domainParams := selectPaceConfig(cardAccess)

		if !paceConfig.oid.Equal(tc.expOid) {
			t.Errorf("Invalid PACE OID (%s)", paceConfig.oid)
		}

		if (domainParams.isECDH != tc.expIsEcdh) || (domainParams.ec != tc.expEc) {
			t.Errorf("Invaid domain-params (1)")
		}
	}
}

func TestDoPaceNoCardAccessFile(t *testing.T) {
	var err error
	var doc document.Document
	var transceiver *iso7816.MockTransceiver = new(iso7816.MockTransceiver)
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(transceiver)

	var pass *password.Password
	pass, err = password.NewPasswordMrzi("T22000129", "640812", "101031")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	var pace *Pace = NewPace(nfc, &doc, pass)

	err = pace.DoPACE()
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// verify that PACE was not performed (i.e. no secure-messaging)
	if nfc.SM != nil {
		t.Errorf("Secure-messaging not expected")
	}
}

// PACE test for GM (ECDH) based on worked example in ICAO9303 p11 specs (Appendix G1)
func TestDoPace_GM_ECDH(t *testing.T) {
	var nfc *iso7816.NfcSession

	{
		var transceiver *iso7816.MockTransceiver = new(iso7816.MockTransceiver)

		// add in expected request/response tuples
		transceiver.AddReqRsp("0022C1A40F800A04007F00070202040202830101", "9000")
		transceiver.AddReqRsp("10860000027C0000", "7C12801095A3A016522EE98D01E76CB6B98B42C39000")
		transceiver.AddReqRsp("10860000457C438141047ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D00", "7C43824104824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F5730D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C549000")
		transceiver.AddReqRsp("10860000457C438341042DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB3646200", "7C438441049E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F0949000")
		transceiver.AddReqRsp("008600000C7C0A8508C2B0BD78D94BA86600", "7C0A86083ABB9674BCE93C089000")

		nfc = iso7816.NewNfcSession(transceiver)
	}

	// setup static EC keys for test
	getTestKeyGenEc := func() func(ec elliptic.Curve) cryptoutils.EcKeypair {
		var idx int

		return func(ec elliptic.Curve) cryptoutils.EcKeypair {
			var tmpPri *big.Int
			var tmpPub *cryptoutils.EcPoint = new(cryptoutils.EcPoint)

			switch idx {
			case 0:
				tmpPri, _ = new(big.Int).SetString("7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99", 16)
				tmpPub.X, _ = new(big.Int).SetString("7ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E", 16)
				tmpPub.Y, _ = new(big.Int).SetString("544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D", 16)
			case 1:
				tmpPri, _ = new(big.Int).SetString("A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595", 16)
				// NB set public-key to dummy value as it should be manually calculated using the mapped generator (Gx/y)
				//    - this way we can test that Gxy is getting propagated from earlier step and flow is working correcvtly
				tmpPub.X = big.NewInt(0)
				tmpPub.Y = big.NewInt(0)
			default:
				t.Errorf("Invalid key-gen index (idx:%1d)", idx)
			}

			idx++

			return cryptoutils.EcKeypair{Pri: tmpPri.Bytes(), Pub: tmpPub}
		}
	}

	var err error
	var doc document.Document

	// PACEInfo: 3012060A 04007F00 07020204 02020201 0202010D
	//				** NB added 3114 to start
	doc.Mf.CardAccess, err = document.NewCardAccess(utils.HexToBytes("31143012060A04007F0007020204020202010202010D"))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// password (MRZ)
	var pass *password.Password
	pass, err = password.NewPasswordMrzi("T22000129", "640812", "101031")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	var pace *Pace = NewPace(nfc, &doc, pass)

	// override EC key-generator (to ensure predictable keys)
	pace.keyGeneratorEc = getTestKeyGenEc()

	err = pace.DoPACE()
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// verify Secure-Messaging was setup correctly
	{
		smExp, err := iso7816.NewSecureMessaging(cryptoutils.AES, utils.HexToBytes("F5F0E35C0D7161EE6724EE513A0D9A7F"), utils.HexToBytes("FE251C7858B356B24514B3BD5F4297D1"))
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		// NB SSC should be 0's

		if !nfc.SM.Equal(*smExp) {
			t.Errorf("SecureMessaging differs to expected")
		}
	}

	// verify chip-auth-status is NA
	if doc.ChipAuthStatus != document.CHIP_AUTH_STATUS_NONE {
		t.Errorf("ChipAuthStatus != NONE")
	}

}

// PACE test for GM (ECDH) using TDES/CBC (NZ)
func TestDoPace_GM_ECDH_TDES_CBC_NZ(t *testing.T) {
	var nfc *iso7816.NfcSession

	{
		var transceiver *iso7816.MockTransceiver = new(iso7816.MockTransceiver)

		// add in expected request/response tuples
		transceiver.AddReqRsp("0022c1a40f800a04007f00070202040201830101", "9000")
		transceiver.AddReqRsp("10860000027c0000", "7c128010b88382812290017af1cc906ff00e7f4d9000")
		transceiver.AddReqRsp("10860000457c438141047706b2b6246ab4612229b8a11212ddba7fea0568c9c0975dee22c0e3dd3a3f0321e8afee836e373b570d24000d56fb195104d486e63321ff8c819dd5ee018dcb00", "7c43824104780b4edec9b926f9f964fad826d9990a667608d96ba7b397ae8609b6533e0d036d148365ddf4e5ff6611c2b62aa17fc9899f327bc929db543e7abd0ee724e4be9000")
		transceiver.AddReqRsp("10860000457c43834104507a0156efae8fb8acc519036c0b2fe0393c878744c7f91878ee4e07a41412ba5c0753d68a44a91e9f57f3f992ab689e6c2065d3b2a27c3658a4fd632931ee3800", "7c438441042dbaf62e6fdfb31eb66f206493b9e7721586f0e5c93754d7bd5a884ca251ee4d720ab539a60561bc46812fa289b58ac69f0c6e32adbaf7241049a31211f80f5b9000")
		transceiver.AddReqRsp("008600000c7c0a85088d7c617d43efe09e00", "7c0a8608cb57047c809079f69000")

		nfc = iso7816.NewNfcSession(transceiver)
	}

	// setup static EC keys for test
	getTestKeyGenEc := func() func(ec elliptic.Curve) cryptoutils.EcKeypair {
		var idx int

		return func(ec elliptic.Curve) cryptoutils.EcKeypair {
			var tmpPri *big.Int
			var tmpPub *cryptoutils.EcPoint = new(cryptoutils.EcPoint)

			switch idx {
			case 0:
				tmpPri, _ = new(big.Int).SetString("2808272c0ec20e01a3450030ef32855e9feb5cb17719e985389b1cf47609e69f", 16)
				tmpPub.X, _ = new(big.Int).SetString("7706b2b6246ab4612229b8a11212ddba7fea0568c9c0975dee22c0e3dd3a3f03", 16)
				tmpPub.Y, _ = new(big.Int).SetString("21e8afee836e373b570d24000d56fb195104d486e63321ff8c819dd5ee018dcb", 16)
			case 1:
				tmpPri, _ = new(big.Int).SetString("8f89449052df6c7983750c7b042c3cea12b36819174424c7cd28153f7b70b402", 16)
				// NB set public-key to dummy value as it should be manually calculated using the mapped generator (Gx/y)
				//    - this way we can test that Gxy is getting propagated from earlier step and flow is working correcvtly
				tmpPub.X = big.NewInt(0)
				tmpPub.Y = big.NewInt(0)
			default:
				t.Errorf("Invalid key-gen index (idx:%1d)", idx)
			}

			idx++

			return cryptoutils.EcKeypair{Pri: tmpPri.Bytes(), Pub: tmpPub}
		}
	}

	var err error
	var doc document.Document

	doc.Mf.CardAccess, err = document.NewCardAccess(utils.HexToBytes("31143012060a04007f0007020204020102010202010d"))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// password (MRZ)
	var pass *password.Password
	pass, err = password.NewPasswordMrzi("LM277954", "781214", "271115")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	var pace *Pace = NewPace(nfc, &doc, pass)

	// override EC key-generator (to ensure predictable keys)
	pace.keyGeneratorEc = getTestKeyGenEc()

	err = pace.DoPACE()
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// verify Secure-Messaging was setup correctly
	{
		smExp, err := iso7816.NewSecureMessaging(cryptoutils.TDES, utils.HexToBytes("430e4c8c38dfefaed92067b919a897f8"), utils.HexToBytes("c1bc1f075797b970b5a45e64a764b0cb"))
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		// NB SSC should be 0's

		if !nfc.SM.Equal(*smExp) {
			t.Errorf("SecureMessaging differs to expected")
		}
	}

	// verify chip-auth-status is NA
	if doc.ChipAuthStatus != document.CHIP_AUTH_STATUS_NONE {
		t.Errorf("ChipAuthStatus != NONE")
	}

}

func TestDoPace_CAM_ECDH_DE(t *testing.T) {
	var nfc *iso7816.NfcSession

	{
		var transceiver *iso7816.MockTransceiver = new(iso7816.MockTransceiver)

		// add in expected request/response tuples
		transceiver.AddReqRsp("0022c1a40f800a04007f00070202040602830101", "9000")
		transceiver.AddReqRsp("10860000027c0000", "7c1280109bff93e6ed9f5f9764ec0d783d14fb039000")
		transceiver.AddReqRsp("10860000457c43814104303f340815eea501772393e299a4a6f6694600189c249c63a8513ff3fefa66e346d11970b5f76fb564c3b0e54b215528f647ec5a9ab209cdbe262e763d6119a100", "7c4382410476dc295c4fb14237d87318d70967e25ec45f74d6fd4aff588c90efb3d868f05b450ba6b64967227c2246dbe2905522c8086dac7f3bbe5cf3b192f0a0c2d97ee59000")
		transceiver.AddReqRsp("10860000457c438341048442b191ef5346a6b6dacb6cd5728c4a72f0ca7aecdf7afdfb3ef175e12a6f7c74f509af768b8dbe2cf42d16c1f00714691d78a19cdf1b493390d1173785f2b700", "7c438441042315ae8143f21de15b35f083cfa148c5fcbd9f2eb9dcdc4519bcf337443e79e55b28a5e218fb919c30880d263e469645ff114c46ed29918910be3453527d21649000")
		transceiver.AddReqRsp("008600000c7c0a8508fee088a4d7be1b7f00", "7c3c860819a2b9192e11512a8a30b3ae8830311b1d5605777f47cb4ed028346cd00105d32859de127da3d8398865358f26f08ebe410864eaf6e39f33f3f59000")
		transceiver.AddReqRsp("0ca4020c1d87110147ee2e3bd440fb596167f2bb6cd6395e8e08a105747484314bcf00", "990290008e085f570baddd1002d29000")
		transceiver.AddReqRsp("0cb000000d9701048e085d283ec183cbb99800", "871101d688d27a6d16f03619e76dcb59c1f1ec990290008e08b7df9a5982bb17299000")
		transceiver.AddReqRsp("0cb000040d9701008e08a893fca2cd1cb17d00", "8781e10191b363a7569f49734c418c91ace47aa27886ffd841802c1402793032b9a15568d16bddd290885c7bb6672c459be06fda2464b3ac216272142d6bdc10e60a8d977143e10b095c1066624a3cae65e422a5ad6faf4b2bbbdf3789e11632fda8317d15db2c6d5b1d77ee46e693afecf0bf6cc227d0106fda370f4a43fd70088362869acd7c55fe00a13c5eafa9f11c217d3a872075209d98709aec16b8a70bc1010497eb4eb2867044b8cb6fba76247b8240036aabf3a179c9adbdacf5cf83506effc723b51af2e2b4868f74e2f9aac7ecc29626ad19a75a1d1469f6123c69b9c223990290008e08ea0238ad4096f04d9000")
		transceiver.AddReqRsp("0cb000e30d9701008e085dcb938a53abd87400", "8781e1011c7177d401c84023ee49f0a6813e1af16b43052d4478a78b0af39b329e7a8f4fc101c9f558527c453e2cfa02b5088b4d64a5e8b8d752c9fc64ab419224f5d6f014e327e16c9adcb5e1bb48b41327b858ab4f3b9f281d5a4735529cc69456f1076ceabb7335f649535bdb25900aca7138f44fc47f96528590c5bc271d411c74750843e39fa282e2068c122534380da8c5617d45040854f773c6b47b5929b6272684a1e95bfddb54334380a63907e028710cb92030f83b49fd76fe5392057e52eef9fc6319c4ac400cf1761a45e34f7f3bb7860bcb1bc230ef00a2a011b8ad2c26990290008e08f18d62f004f604ca9000")
		transceiver.AddReqRsp("0cb001c20d9701008e0800aa6a8873a4a4c700", "8781e1019f74944baea5cb9a628b5320379ba84c9dbbbac678dd60e4d50774e7754ad147d9bd9061cbde486061543a924a5c75ebe1fdef7ecf2f470204d8a76c3f3f7868f53b068de3723f148aa36902252399111484ed660d83a8fbc354aa83f68697619e31b14e24860f43050fb0a4dcd9c04f51a388eb3867f6be33b9a2b3852ddf8b25d7fd93fb26531090cda34854c5761d5fea6bf16cd6b27c6c34a1d9f583a48cca4db08389404bb73bd99030afa1163227e70bce4d0325af1f5bdfa2f5f3e062fef1225c9ea8a7420749d765a9e56bc1a0d64d3cf5560f43daa6eb881a9a7cba990290008e08f128f595abf1b1ed9000")
		transceiver.AddReqRsp("0cb002a10d9701008e08f1b21360dd601aaf00", "8781e1012fabf9e0655d7e987fd28a8aeb19c9cadd990d49399799ed1fe465bcea56da9ba3024291d40d23d7f1e00485d71faddc6d8c1382e8028dd22efdcc72ed47663d56d20dd6c4b867956fe0507313083ae7fc54fb46133f184febbe13ad6fd3e2616a1f4a829e75ada1a0e443ca738288f6014be8a7745d8259b089e6bee35bcc4bf5b63db5fdd84244f67eca099213b70a861b4487225aa68af684278fceb4cb809de42be3ee95b0e0d72bcdb0ed47cb56efc264e04a9397a90e81ad1d81efa2d14b2ca8ec7bd997f4b1c1fd344d5dee8589c38b227ca4cb35810060a7cc76403e990290008e083eb47ef4fa82afc99000")
		transceiver.AddReqRsp("0cb003800d9701008e088fd094ae384388ab00", "8781e101cbb19c8fe8b58b15138915c9b8aff2171c3c2894196d91a338add75a221d1cb763910296468d0c7d8bf9058389e50b7ebc5603797d5ecf832fe25291b9ec414d57e5f75f3597523949c721420dd5a55b8b2738795c60a3b1436168d2188d89b47cc60951db4d558935f87b9c075c82e3e9630315a7a2a7f266ed24973c12207e51ef5c11a1e1e897c79366fae1999087d60b78c537b2b18f2219fb38d9a2b244eb58721def8a2532ce889e4c914eb6add938590fab7e5ef23ba576ad11cb6b6ebd5507dc7097c9c77b68f3cd3951bacac1501f18d838899a2f512eb7e914ff06990290008e086dca6ea612bea2fc9000")
		transceiver.AddReqRsp("0cb0045f0d9701008e087f2ab02f493166d400", "8781e1019f92735420bc040cf99cc0191a80cc02e3c5fc899d535ca2e7204a7855de80c1960a71e99c18a8404ac9dee12e85e9339b384d15718325ccb5e8c64e95c04f20e1e2c3786fceb577020599ccbe62c62ed20070007e8287a8a24ea12c6e7a1b08f5cc4ad822dce924c8f9b4926b889018e2b01c3c3c1cee5601cb40176281cdea3a07905b52289b2c0c2817634a3936fb43501dd67febb2a65cc6341340c0f614f14733cc5eb1a989879695cc0ae521c18a557d79e73459c32ff470e7e38e242e8bd36d9ad6f58d1b33e5df10de3d67edeb5d502aa6760d98744c5cb6300f5340990290008e08f04944fffbcf08499000")
		transceiver.AddReqRsp("0cb0053e0d9701008e080244dd4fff79cc5b00", "8781e1013dc2a051c66e2bbc888d65714ed2652039913671c4301483ac9380f803c262ee89de67e544e564a953ab86edac4ab54f77bbc49000784b3cc323b774ec4ebcb397729ca539baa584099b63ceb56a1334debcbefc4fdace029b4c7292c6519492fe31f422cd021fb7c990c1016b3dd1d550f3cd8a443e267fb0a70106d7933b905008042e7937205d6f13fda86a23f3112dc3ea566460797ca2f46e294a3a7f7afd1c8b723e10cc1c7de5b2e0b8008ebf4d086937a6a419e31719e5e33eec5bdb4dd49bc60648ebdad3cc272961311c54cb552fd40b2f3ad0e560616c89d3c61e990290008e08f84dade3511b07149000")
		transceiver.AddReqRsp("0cb0061d0d9701008e08d13c4e86a5c390bc00", "8781e101cfe5947ea65924c874ec477a1d4be1c587093d874482286e9eac15f241c416bbc1f26f93ec71b3212de17c19e071037831a3c6efa7374c66843965a2ceee6f2ffbc5f1c648fe751b978bdb26c94a418afde1eeceb28ce5124ce58c3c0ec96a62a1a383a1494820dd3db166e0a5e6d632a080f29413e733e44996c99f4a03702abd445df84d4bbeb7e4225fd3bc19d3e8517c474c0ad9c3b53f61d6a2569fb4713f097da18b7395697f7fd996a0771d59a2233536e4e8220fbcabea7add966748cbb61efa21f93ff8b11374a699e2acf8a061bb3c815f0648dbcc36d5a3a138f4990290008e08a6fd912653b4be5e9000")
		transceiver.AddReqRsp("0cb006fc0d97014a8e0834b735e4065d97c100", "8751017c668bedae4a7b51f4466d979d2026942ea1f4ae37bcb6e29f0c4b36f3572675ae58c8b9f52ebf35c65c3ae955dc060bebc79b407f7e86d587391d9535c593e5f790939babe21b1436035b2046560d09990290008e0820085b109fb48aad9000")

		nfc = iso7816.NewNfcSession(transceiver)
	}

	// setup static EC keys for test
	getTestKeyGenEc := func() func(ec elliptic.Curve) cryptoutils.EcKeypair {
		var idx int

		return func(ec elliptic.Curve) cryptoutils.EcKeypair {
			var tmpPri *big.Int
			var tmpPub *cryptoutils.EcPoint = new(cryptoutils.EcPoint)

			switch idx {
			case 0:
				tmpPri, _ = new(big.Int).SetString("01fd26013f5bc41fad8bb09811e435f16fbe2eb3c2e1d999b0f63da8c3d58bb5", 16)
				tmpPub.X, _ = new(big.Int).SetString("303f340815eea501772393e299a4a6f6694600189c249c63a8513ff3fefa66e3", 16)
				tmpPub.Y, _ = new(big.Int).SetString("46d11970b5f76fb564c3b0e54b215528f647ec5a9ab209cdbe262e763d6119a1", 16)
			case 1:
				tmpPri, _ = new(big.Int).SetString("1fcd3d8ac4fae3960a14fea2925d75add335f13b248eba192358dded93a89552", 16)
				// NB set public-key to dummy value as it should be manually calculated using the mapped generator (Gx/y)
				//    - this way we can test that Gxy is getting propagated from earlier step and flow is working correcvtly
				tmpPub.X = big.NewInt(0)
				tmpPub.Y = big.NewInt(0)
			default:
				t.Errorf("Invalid key-gen index (idx:%1d)", idx)
			}

			idx++

			return cryptoutils.EcKeypair{Pri: tmpPri.Bytes(), Pub: tmpPub}
		}
	}

	var err error
	var doc document.Document

	doc.Mf.CardAccess, err = document.NewCardAccess(utils.HexToBytes("31283012060A04007F0007020204020202010202010D3012060A04007F0007020204060202010202010D"))
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// password (MRZ)
	var pass *password.Password
	pass, err = password.NewPasswordMrzi("C4KHNY1PF", "780214", "330315")
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	var pace *Pace = NewPace(nfc, &doc, pass)

	// override EC key-generator (to ensure predictable keys)
	pace.keyGeneratorEc = getTestKeyGenEc()

	err = pace.DoPACE()
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// verify Secure-Messaging state (inc final SSC) is correct
	{
		smExp, err := iso7816.NewSecureMessaging(cryptoutils.AES, utils.HexToBytes("a8e85e938514ec67ae33cda3d43d3c48"), utils.HexToBytes("27f1adeb705a049a305b0c619b14b9b3"))
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		smExp.SetSSC(utils.HexToBytes("00000000000000000000000000000016"))

		if !nfc.SM.Equal(*smExp) {
			t.Errorf("SecureMessaging differs to expected")
		}
	}

	// verify chip-auth-status reflects PACE-CAM was performed
	if doc.ChipAuthStatus != document.CHIP_AUTH_STATUS_PACE_CAM {
		t.Errorf("ChipAuthStatus is not reflecting PACE-CAM")
	}
}

func TestDecodeDynAuthDataError(t *testing.T) {
	// NB we expect an exception when invalid TLV data is passed

	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	var badTlvData []byte = utils.HexToBytes("0104123456") // indicates len=4, but only has 3 bytes of data
	var tag byte = 0x82

	_ = decodeDynAuthData(tag, badTlvData)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}
