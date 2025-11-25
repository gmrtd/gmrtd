package activeauth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/tlv"
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

	var doc *document.Document = &document.Document{}

	var dg15bytes []byte = utils.HexToBytes("6F8201023081FF300D06092A864886F70D01010105000381ED003081E90281E100BB8F93F4DC95E205CDA17C6927AB1E365B13065D03CD12E0FCE95D96840529453202F56CC4C13F77CD062930C8BC89A2873B257045C286E601CF3C09323A53103314902804AA10A314628CE222206A8866946A36B442041BB54AC81E6855DD1D6E16101833D65A191C20AC8B33B8A1A32920F46043F8031CF2BC17417030865FC5BE5A39DEE423BCBA3CA8177168EB23CFE01BA43EC87711B1CFFF85DB46F300DD8AE317B50D543B573E119E23AF7070D0B2FED6A3B2313A5EC02A531AAED1741F4390D1013E2A0F081EAC5DC8B0A1B2C6BDB1206F08D30E3643E1E5BDF536110203010001")

	err = doc.NewDG(15, dg15bytes)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	var activeAuth *ActiveAuth = NewActiveAuth(nfc, doc)

	activeAuth.randomBytesFn = getTestRandomBytesFn()

	err = activeAuth.DoActiveAuth()
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

func TestDoActiveAuthChipStatusErr(t *testing.T) {
	var doc *document.Document = &document.Document{}

	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(new(iso7816.MockTransceiver))

	var activeAuth *ActiveAuth = NewActiveAuth(nfc, doc)

	// NB indicate ChipAuth performed elsewhere (CA) to skip AA
	doc.ChipAuthStatus = document.CHIP_AUTH_STATUS_CA

	err := activeAuth.DoActiveAuth()

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if doc.ChipAuthStatus != document.CHIP_AUTH_STATUS_CA {
		t.Errorf("Unexpected Chip Auth status")
	}
}

func TestDoActiveAuthMissingDg15Err(t *testing.T) {
	var doc *document.Document = &document.Document{}

	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(new(iso7816.MockTransceiver))

	var activeAuth *ActiveAuth = NewActiveAuth(nfc, doc)

	err := activeAuth.DoActiveAuth()

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if doc.ChipAuthStatus != document.CHIP_AUTH_STATUS_NONE {
		t.Errorf("Unexpected Chip Auth status")
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

// TestDecodeFWithLeadingZeros tests that decodeF correctly handles data with leading zeros
// This simulates the scenario where RsaDecryptWithPublicKey preserves leading zeros
// but those zeros are not part of the ISO/IEC 9796-2 format
func TestDecodeFWithLeadingZeros(t *testing.T) {
	// Create valid ISO/IEC 9796-2 formatted data (SHA-256)
	validData := utils.HexToBytes("6A1234567890ABCDEF1234567890ABCDEF11223344783980d44fd3a80f0e4210eb9c73ea399932062d465438f8e1ff13377de8308934CC")

	// Add leading zeros (simulating what RsaDecryptWithPublicKey might return after the fix)
	dataWithLeadingZeros := append([]byte{0x00, 0x00}, validData...)

	// The current implementation should fail without trimming
	_, _, _, err := decodeF(dataWithLeadingZeros)
	if err == nil {
		t.Error("Expected error when decodeF receives data with leading zeros")
	}

	// But after trimming, it should work
	trimmed := utils.TrimLeadingZeroBytes(dataWithLeadingZeros)
	m1, d, hashAlg, err := decodeF(trimmed)
	if err != nil {
		t.Errorf("Unexpected error after trimming: %s", err)
	}

	// Verify the decoded values
	expM1 := utils.HexToBytes("1234567890ABCDEF1234567890ABCDEF11223344")
	expD := utils.HexToBytes("783980d44fd3a80f0e4210eb9c73ea399932062d465438f8e1ff13377de83089")

	if !bytes.Equal(m1, expM1) {
		t.Errorf("Incorrect m1 (Exp:%x) (Act:%x)", expM1, m1)
	}

	if !bytes.Equal(d, expD) {
		t.Errorf("Incorrect d (Exp:%x) (Act:%x)", expD, d)
	}

	if hashAlg != crypto.SHA256 {
		t.Errorf("Incorrect hashAlg (Exp:%d) (Act:%d)", crypto.SHA256, hashAlg)
	}
}

func TestDoInternalAuthenticateNoRspErr(t *testing.T) {
	var doc document.Document
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{})
	var aa *ActiveAuth = NewActiveAuth(nfc, &doc)
	var rndIfd []byte = make([]byte, 20)

	_, err := aa.doInternalAuthenticate(rndIfd)
	// NB expect error due to lack of RApdu response
	if err == nil {
		t.Errorf("expected error")
	}
}

func TestDoInternalAuthenticateCardDeadErr(t *testing.T) {
	var doc document.Document
	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(&iso7816.StaticTransceiver{RApdu: utils.HexToBytes("6FFF")}) // NB 6FFF = Card Dead
	var aa *ActiveAuth = NewActiveAuth(nfc, &doc)
	var rndIfd []byte = make([]byte, 20)

	_, err := aa.doInternalAuthenticate(rndIfd)
	// NB expect error due to RApdu error
	if err == nil {
		t.Errorf("expected error")
	}
}

// Build DG15 from an EC public key: DG15 = 0x6F || len || SPKI
func makeDG15FromECPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	node := tlv.NewTlvSimpleNode(0x6F, spki)
	return node.Encode(), nil
}

// Fixed-width concat r||s (each padded to curve size)
func concatRSFixed(curve elliptic.Curve, r, s *big.Int) []byte {
	nb := (curve.Params().BitSize + 7) / 8
	rb := leftPad(r.Bytes(), nb)
	sb := leftPad(s.Bytes(), nb)
	out := make([]byte, 0, nb*2)
	out = append(out, rb...)
	out = append(out, sb...)
	return out
}

func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func TestEcdsaValidateActiveAuthSignatureAllCurves(t *testing.T) {
	type testCase struct {
		name      string
		dg15bytes []byte
		rndIfd    []byte
		signature []byte
		expectErr bool
	}

	var cases []testCase

	// Programmatically generated DG15s for various curves
	curves := []struct {
		name string
		ec   elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, c := range curves {
		priv, err := ecdsa.GenerateKey(c.ec, rand.Reader)
		if err != nil {
			t.Fatalf("keygen %s: %v", c.name, err)
		}
		dg15, err := makeDG15FromECPublicKey(&priv.PublicKey)
		if err != nil {
			t.Fatalf("DG15 build %s: %v", c.name, err)
		}

		rndIfd := cryptoutils.RandomBytes(8)
		hashAlg := cryptoutils.CryptoHashFromEcPubKey(&priv.PublicKey) // your util: should map P-256->SHA-256, P-384->SHA-384, P-521->SHA-512 (commonly)
		hash := cryptoutils.CryptoHash(hashAlg, rndIfd)

		r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
		if err != nil {
			t.Fatalf("sign %s: %v", c.name, err)
		}
		sig := concatRSFixed(c.ec, r, s)

		// Positive
		cases = append(cases, testCase{
			name:      c.name + " valid",
			dg15bytes: dg15,
			rndIfd:    rndIfd,
			signature: sig,
			expectErr: false,
		})

		// Negative: wrong nonce (re-hash different rnd)
		wrongRnd := cryptoutils.RandomBytes(8)
		cases = append(cases, testCase{
			name:      c.name + " wrong nonce",
			dg15bytes: dg15,
			rndIfd:    wrongRnd,
			signature: sig,
			expectErr: true,
		})

		// Negative: bit-flip signature (still correct length)
		bad := make([]byte, len(sig))
		copy(bad, sig)
		bad[0] ^= 0xFF
		cases = append(cases, testCase{
			name:      c.name + " invalid signature",
			dg15bytes: dg15,
			rndIfd:    rndIfd,
			signature: bad,
			expectErr: true,
		})
	}

	for _, tc := range cases {
		doc := &document.Document{}
		if err := doc.NewDG(15, tc.dg15bytes); err != nil {
			t.Errorf("%s: NewDG(15, ...) error: %v", tc.name, err)
			continue
		}
		aa := NewActiveAuth(nil, doc)
		err := aa.ValidateActiveAuthSignature(tc.signature, tc.rndIfd)
		if tc.expectErr && err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		}
	}
}
