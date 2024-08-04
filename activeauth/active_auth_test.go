package activeauth

import (
	"bytes"
	"crypto"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/utils"
)

func TestDoActiveAuth(t *testing.T) {
	// "doActiveAuth","SM(pre)":"(alg:1, ksenc:b99d546108eaa251570876b6d3456dce, ksmac:e3857ca24946251c151c540e13f2cd51, ssc:00000000000000cc)"}
	//
	// DG15: 6F8201023081FF300D06092A864886F70D01010105000381ED003081E90281E100BB8F93F4DC95E205CDA17C6927AB1E365B13065D03CD12E0FCE95D96840529453202F56CC4C13F77CD062930C8BC89A2873B257045C286E601CF3C09323A53103314902804AA10A314628CE222206A8866946A36B442041BB54AC81E6855DD1D6E16101833D65A191C20AC8B33B8A1A32920F46043F8031CF2BC17417030865FC5BE5A39DEE423BCBA3CA8177168EB23CFE01BA43EC87711B1CFFF85DB46F300DD8AE317B50D543B573E119E23AF7070D0B2FED6A3B2313A5EC02A531AAED1741F4390D1013E2A0F081EAC5DC8B0A1B2C6BDB1206F08D30E3643E1E5BDF536110203010001
	// RND.IFD: 96302b0f3d7e7864
	//
	// cAPDU: 0c88000020871101ed7f8cb47a4eea086324a7f9dd7427809701008e0897f54bae49aa71f800
	// rAPDU: 8781e901d04ca80f527df94f4a430d3d6e6cb6c2af4c6756c068a93132d147fa27833125304132981b8bd8009448e89f259eec8552b54285cef9d8f1b7fb31b9f279221c7e925f4951811f3fe2e01d76e68dbc7cde9c873c5f61862f3c5469792a72f92c8943b890436f5e9feaead9f2a361fcd7a615493d1b3519865f32ee9a125886588eb21fee0e709353d0731139fdc958d6b2127fad6947b438998b526819803f70f78614cd42f4a6619c6af95dfd2ab09bedf71e707abc39a250aee68006d522ad37d159674984a07d11c001022c853aeb7acdb059ede5721a3b9f20441bda7e242ee8df1369d25316990290008e08fd2493147866f0ed9000
	//
	// AA enabled

	var err error

	var nfc *iso7816.NfcSession

	{
		var transceiver *iso7816.MockTransceiver = new(iso7816.MockTransceiver)

		// add in expected request/response tuples
		transceiver.AddReqRsp("0c88000020871101ed7f8cb47a4eea086324a7f9dd7427809701008e0897f54bae49aa71f800", "8781e901d04ca80f527df94f4a430d3d6e6cb6c2af4c6756c068a93132d147fa27833125304132981b8bd8009448e89f259eec8552b54285cef9d8f1b7fb31b9f279221c7e925f4951811f3fe2e01d76e68dbc7cde9c873c5f61862f3c5469792a72f92c8943b890436f5e9feaead9f2a361fcd7a615493d1b3519865f32ee9a125886588eb21fee0e709353d0731139fdc958d6b2127fad6947b438998b526819803f70f78614cd42f4a6619c6af95dfd2ab09bedf71e707abc39a250aee68006d522ad37d159674984a07d11c001022c853aeb7acdb059ede5721a3b9f20441bda7e242ee8df1369d25316990290008e08fd2493147866f0ed9000")

		nfc = iso7816.NewNfcSession(transceiver)
	}

	// setup SM
	{
		nfc.SM, err = iso7816.NewSecureMessaging(cryptoutils.TDES, utils.HexToBytes("b99d546108eaa251570876b6d3456dce"), utils.HexToBytes("e3857ca24946251c151c540e13f2cd51"))
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		nfc.SM.SetSSC(utils.HexToBytes("00000000000000cc"))
	}

	// setup static randoms for test
	getTestRandomBytesFn := func() func(length int) []byte {
		var idx int

		return func(length int) []byte {
			var out []byte

			switch idx {
			case 0:
				out = utils.HexToBytes("96302b0f3d7e7864")
			default:
				t.Errorf("Invalid index (idx:%1d)", idx)
			}

			// sanity check that length matches requested amount
			if len(out) != length {
				t.Errorf("Test data length does NOT match amount requested (req:%d, act:%d)", length, len(out))
			}

			idx++

			return out
		}
	}

	var doc document.Document

	var dg15bytes []byte = utils.HexToBytes("6F8201023081FF300D06092A864886F70D01010105000381ED003081E90281E100BB8F93F4DC95E205CDA17C6927AB1E365B13065D03CD12E0FCE95D96840529453202F56CC4C13F77CD062930C8BC89A2873B257045C286E601CF3C09323A53103314902804AA10A314628CE222206A8866946A36B442041BB54AC81E6855DD1D6E16101833D65A191C20AC8B33B8A1A32920F46043F8031CF2BC17417030865FC5BE5A39DEE423BCBA3CA8177168EB23CFE01BA43EC87711B1CFFF85DB46F300DD8AE317B50D543B573E119E23AF7070D0B2FED6A3B2313A5EC02A531AAED1741F4390D1013E2A0F081EAC5DC8B0A1B2C6BDB1206F08D30E3643E1E5BDF536110203010001")

	err = doc.NewDG(15, dg15bytes)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	var activeAuth *ActiveAuth = NewActiveAuth()

	activeAuth.randomBytesFn = getTestRandomBytesFn()

	err = activeAuth.DoActiveAuth(nfc, &doc)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if doc.ChipAuthStatus != document.CHIP_AUTH_STATUS_AA {
		t.Errorf("Incorrect ChipAuth State (Exp:%1d, Act:%01d)", document.CHIP_AUTH_STATUS_AA, doc.ChipAuthStatus)
	}

	// verify Secure-Messaging post-state is correct
	// NB active-auth does NOT setup a new SM, do we just sanity check that it's still there with the correct SSC (ie +2)
	{
		smExp, err := iso7816.NewSecureMessaging(cryptoutils.TDES, utils.HexToBytes("b99d546108eaa251570876b6d3456dce"), utils.HexToBytes("e3857ca24946251c151c540e13f2cd51"))
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		smExp.SetSSC(utils.HexToBytes("00000000000000ce"))

		if !nfc.SM.Equal(*smExp) {
			t.Errorf("SecureMessaging differs to expected")
		}
	}

}

func TestDecodeF(t *testing.T) {
	testCases := []struct {
		rndIfd     []byte
		f          []byte
		expM1      []byte
		expD       []byte
		expHashAlg crypto.Hash
	}{
		{
			// SHA-1
			rndIfd:     utils.HexToBytes("0102030405060708"),
			f:          utils.HexToBytes("6A1234567890ABCDEF1234567890ABCDEF11223344e9b287952a913cc5b60ff74ecfc87e40e81563b1BC"),
			expM1:      utils.HexToBytes("1234567890ABCDEF1234567890ABCDEF11223344"),
			expD:       utils.HexToBytes("e9b287952a913cc5b60ff74ecfc87e40e81563b1"),
			expHashAlg: crypto.SHA1,
		},
		{
			// SHA-224
			rndIfd:     utils.HexToBytes("0102030405060708"),
			f:          utils.HexToBytes("6A1234567890ABCDEF1234567890ABCDEF11223344aefc05e88f48eb88d367ba3dacb7d6a8543ec02bd315e47ddbe2045d38CC"),
			expM1:      utils.HexToBytes("1234567890ABCDEF1234567890ABCDEF11223344"),
			expD:       utils.HexToBytes("aefc05e88f48eb88d367ba3dacb7d6a8543ec02bd315e47ddbe2045d"),
			expHashAlg: crypto.SHA224,
		},
		{
			// SHA-256
			rndIfd:     utils.HexToBytes("0102030405060708"),
			f:          utils.HexToBytes("6A1234567890ABCDEF1234567890ABCDEF11223344783980d44fd3a80f0e4210eb9c73ea399932062d465438f8e1ff13377de8308934CC"),
			expM1:      utils.HexToBytes("1234567890ABCDEF1234567890ABCDEF11223344"),
			expD:       utils.HexToBytes("783980d44fd3a80f0e4210eb9c73ea399932062d465438f8e1ff13377de83089"),
			expHashAlg: crypto.SHA256,
		},
		{
			// SHA-384
			rndIfd:     utils.HexToBytes("0102030405060708"),
			f:          utils.HexToBytes("6A1234567890ABCDEF1234567890ABCDEF112233448e0873b0baf595a777b497779981bd94dda3a81fd61cf2d526ab490f2d6cbcecc6eab5804df4e0a70169d4d0d6c07e7536CC"),
			expM1:      utils.HexToBytes("1234567890ABCDEF1234567890ABCDEF11223344"),
			expD:       utils.HexToBytes("8e0873b0baf595a777b497779981bd94dda3a81fd61cf2d526ab490f2d6cbcecc6eab5804df4e0a70169d4d0d6c07e75"),
			expHashAlg: crypto.SHA384,
		},
		{
			// SHA-512
			rndIfd:     utils.HexToBytes("0102030405060708"),
			f:          utils.HexToBytes("6A1234567890ABCDEF1234567890ABCDEF11223344968304e09f0c0ec86be4ade4b82d97d04283e3652b61193856c9ede1dac8962b3da9580fd77e9f9ef18a24c517d8d3b05f4eeb177e990ae1e80895c8bb28f51635CC"),
			expM1:      utils.HexToBytes("1234567890ABCDEF1234567890ABCDEF11223344"),
			expD:       utils.HexToBytes("968304e09f0c0ec86be4ade4b82d97d04283e3652b61193856c9ede1dac8962b3da9580fd77e9f9ef18a24c517d8d3b05f4eeb177e990ae1e80895c8bb28f516"),
			expHashAlg: crypto.SHA512,
		},
	}
	for _, tc := range testCases {
		m1, d, hashAlg, err := decodeF(tc.f)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		if !bytes.Equal(m1, tc.expM1) {
			t.Errorf("Incorrect m1 (Exp:%x) (Act:%x)", tc.expM1, m1)
		}

		if !bytes.Equal(d, tc.expD) {
			t.Errorf("Incorrect d (Exp:%x) (Act:%x)", tc.expD, d)
		}

		if hashAlg != tc.expHashAlg {
			t.Errorf("Incorrect hashAlg (Exp:%1d) (Act:%1d)", tc.expHashAlg, hashAlg)
		}

		// sanity check that hash works
		// NB this also verifies that the underlying hashAlg is linked
		{
			var m []byte = bytes.Clone(m1)
			m = append(m, tc.rndIfd...)

			calcD := cryptoutils.CryptoHash(hashAlg, m)

			if !bytes.Equal(calcD, d) {
				t.Errorf("Hash sanithy-check failed for constructed 'm' (Exp:%x) (Act:%x)", calcD, d)
			}
		}
	}
}

func TestDecodeFerrors(t *testing.T) {
	testCases := []struct {
		f []byte
	}{
		{
			// no-data
			f: nil,
		},
		{
			// bad header byte - not 0x6A
			f: utils.HexToBytes("6B000000"),
		},
		{
			// bad trailer byte (last byte)
			f: utils.HexToBytes("6A000000"),
		},
		{
			// bad trailer byte (2nd last byte)
			f: utils.HexToBytes("6A0000CC"),
		},
		{
			// sha-1, but too short to even extract the digest (d)
			f: utils.HexToBytes("6Ab287952a913cc5b60ff74ecfc87e40e81563b1BC"),
		},
	}
	for _, tc := range testCases {
		m1, d, hashAlg, err := decodeF(tc.f)

		if err == nil {
			t.Errorf("Error expected")
		}

		if len(m1) > 0 || len(d) > 0 || hashAlg != 0 {
			t.Errorf("Defaults expected for m1(%x),d(%x),hashAlg(%d)", m1, d, hashAlg)
		}
	}

}
