package activeauth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"reflect"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/oid"
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
		sm, err := iso7816.NewSecureMessaging(cryptoutils.TDES, utils.HexToBytes("b99d546108eaa251570876b6d3456dce"), utils.HexToBytes("e3857ca24946251c151c540e13f2cd51"))
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}
		sm.SetSSC(utils.HexToBytes("00000000000000cc"))
		nfc.SetSecureMessaging(sm)
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

	var activeAuth *ActiveAuth = NewActiveAuth(nfc, &doc)

	activeAuth.randomBytesFn = getTestRandomBytesFn()

	var result *document.ActiveAuthResult

	result, err = activeAuth.DoActiveAuth()
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// verify Result is as expected
	var expResult *document.ActiveAuthResult = &document.ActiveAuthResult{Success: true, Algorithm: oid.OidRsaEncryption, Nonce: utils.HexToBytes("96302b0f3d7e7864"), Signature: utils.HexToBytes("474256306840c0ab1b63c10e1c26bdfef4a0dd843920283cc4e6e70a60f2bd25dc7725f9677bc1cde66379dc28b38e8490f33afb2d10f9980c44c0bfc175d2b6684218f535c92fdd3e18db770a9ccbf91db3c7f0138e6d9e94b9bc8371761e3abed5e5e9b260279cfb238b58ae0d6a01da51c74c2a3ecd62c448bd9f20127f7384587287fa971204234e55b1a856c3e5aaaa620bb799a68fbae08ee132bb61683eba9b0b40dc1e54641cad975b16991cab50af82e3f3985afd19e7427a125f5b4b9878b12a5d2e01c7eedca3bb41c6fc05dccd818bce379d04b1f2f5d43487d3")}
	if !reflect.DeepEqual(result, expResult) {
		t.Errorf("Result differs to expected [Act] %+v [Exp] %+v", result, expResult)
	}

	// verify Secure-Messaging post-state is correct
	// NB active-auth does NOT setup a new SM, do we just sanity check that it's still there with the correct SSC (ie +2)
	{
		smExp, err := iso7816.NewSecureMessaging(cryptoutils.TDES, utils.HexToBytes("b99d546108eaa251570876b6d3456dce"), utils.HexToBytes("e3857ca24946251c151c540e13f2cd51"))
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}

		smExp.SetSSC(utils.HexToBytes("00000000000000ce"))

		var smAct *iso7816.SecureMessaging = nfc.SM().(*iso7816.SecureMessaging)
		if !smExp.Equal(*smAct) {
			t.Errorf("SecureMessaging differs to expected")
		}
	}

}

func TestDoActiveAuthMissingDg15(t *testing.T) {
	var doc document.Document

	var nfc *iso7816.NfcSession = iso7816.NewNfcSession(new(iso7816.MockTransceiver))

	var activeAuth *ActiveAuth = NewActiveAuth(nfc, &doc)

	result, err := activeAuth.DoActiveAuth()

	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if result != nil {
		t.Errorf("Unexpected result")
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

// DER/ASN.1 encoded signature (X9.62 format, used by some national ID cards)
func encodeDERSignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
}

func TestEcdsaValidateActiveAuthSignatureAllCurves(t *testing.T) {
	type testCase struct {
		name             string
		dg15bytes        []byte
		rndIfd           []byte
		signature        []byte
		expectErr        bool
		expResultSuccess bool
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
			name:             c.name + " valid",
			dg15bytes:        dg15,
			rndIfd:           rndIfd,
			signature:        sig,
			expectErr:        false,
			expResultSuccess: true,
		})

		// Negative: wrong nonce (re-hash different rnd)
		wrongRnd := cryptoutils.RandomBytes(8)
		cases = append(cases, testCase{
			name:             c.name + " wrong nonce",
			dg15bytes:        dg15,
			rndIfd:           wrongRnd,
			signature:        sig,
			expectErr:        true,
			expResultSuccess: false,
		})

		// Negative: bit-flip signature (still correct length)
		bad := make([]byte, len(sig))
		copy(bad, sig)
		bad[0] ^= 0xFF
		cases = append(cases, testCase{
			name:             c.name + " invalid signature",
			dg15bytes:        dg15,
			rndIfd:           rndIfd,
			signature:        bad,
			expectErr:        true,
			expResultSuccess: false,
		})
	}

	for _, tc := range cases {
		var err error
		var dg15 *document.DG15

		dg15, err = document.NewDG15(tc.dg15bytes)
		if err != nil {
			t.Errorf("%s: NewDG(15, ...) error: %v", tc.name, err)
			continue
		}

		var aaResult *document.ActiveAuthResult

		aaResult, err = ValidateActiveAuthSignature(dg15, tc.signature, tc.rndIfd)
		if tc.expectErr && err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		}
		// check result 'success'
		if aaResult.Success != tc.expResultSuccess {
			t.Errorf("Result 'success' differs to expected [act] %t [exp] %t", aaResult.Success, tc.expResultSuccess)

		}
	}
}

// TestEcdsaValidateActiveAuthSignatureDERFormat tests that DER-encoded ECDSA signatures
// are correctly validated. This format is used by some national ID cards (e.g., Portuguese
// Cartão de Cidadão) instead of the plain r||s format specified in ICAO 9303.
func TestEcdsaValidateActiveAuthSignatureDERFormat(t *testing.T) {
	type testCase struct {
		name             string
		dg15bytes        []byte
		rndIfd           []byte
		signature        []byte
		expectErr        bool
		expResultSuccess bool
	}

	var cases []testCase

	// Test DER-encoded signatures for various curves
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
		hashAlg := cryptoutils.CryptoHashFromEcPubKey(&priv.PublicKey)
		hash := cryptoutils.CryptoHash(hashAlg, rndIfd)

		r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
		if err != nil {
			t.Fatalf("sign %s: %v", c.name, err)
		}

		// Create DER-encoded signature
		derSig, err := encodeDERSignature(r, s)
		if err != nil {
			t.Fatalf("DER encode %s: %v", c.name, err)
		}

		// Positive: valid DER-encoded signature
		cases = append(cases, testCase{
			name:             c.name + " DER valid",
			dg15bytes:        dg15,
			rndIfd:           rndIfd,
			signature:        derSig,
			expectErr:        false,
			expResultSuccess: true,
		})

		// Negative: DER-encoded signature with wrong nonce
		wrongRnd := cryptoutils.RandomBytes(8)
		cases = append(cases, testCase{
			name:             c.name + " DER wrong nonce",
			dg15bytes:        dg15,
			rndIfd:           wrongRnd,
			signature:        derSig,
			expectErr:        true,
			expResultSuccess: false,
		})

		// Negative: corrupted DER signature
		badDer := make([]byte, len(derSig))
		copy(badDer, derSig)
		// Corrupt the r value (skip the header bytes)
		if len(badDer) > 10 {
			badDer[8] ^= 0xFF
		}
		cases = append(cases, testCase{
			name:             c.name + " DER corrupted",
			dg15bytes:        dg15,
			rndIfd:           rndIfd,
			signature:        badDer,
			expectErr:        true,
			expResultSuccess: false,
		})
	}

	for _, tc := range cases {
		var err error
		var dg15 *document.DG15

		dg15, err = document.NewDG15(tc.dg15bytes)
		if err != nil {
			t.Errorf("%s: NewDG15 error: %v", tc.name, err)
			continue
		}

		var aaResult *document.ActiveAuthResult

		aaResult, err = ValidateActiveAuthSignature(dg15, tc.signature, tc.rndIfd)
		if tc.expectErr && err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("%s: unexpected error: %v", tc.name, err)
		}
		if aaResult.Success != tc.expResultSuccess {
			t.Errorf("%s: Result 'success' differs to expected [act] %t [exp] %t", tc.name, aaResult.Success, tc.expResultSuccess)
		}
	}
}

// TestParseEcdsaSignaturePlain tests the parseEcdsaSignaturePlain function
func TestParseEcdsaSignaturePlain(t *testing.T) {
	curve := elliptic.P256()
	curveByteLen := (curve.Params().BitSize + 7) / 8

	// Generate a valid signature
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	hash := cryptoutils.CryptoHash(crypto.SHA256, []byte("test data"))
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	t.Run("valid plain format", func(t *testing.T) {
		plainSig := concatRSFixed(curve, r, s)
		sig, err := parseEcdsaSignaturePlain(plainSig)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if sig.R.Cmp(r) != 0 {
			t.Errorf("R mismatch: got %v, want %v", sig.R, r)
		}
		if sig.S.Cmp(s) != 0 {
			t.Errorf("S mismatch: got %v, want %v", sig.S, s)
		}
	})

	t.Run("empty signature", func(t *testing.T) {
		_, err := parseEcdsaSignaturePlain([]byte{})
		if err == nil {
			t.Error("expected error for empty signature")
		}
	})

	t.Run("odd length rejected", func(t *testing.T) {
		oddSig := make([]byte, curveByteLen*2+1)
		_, err := parseEcdsaSignaturePlain(oddSig)
		if err == nil {
			t.Error("expected error for odd-length signature")
		}
	})

	t.Run("invalid 0 values", func(t *testing.T) {
		zeroSig := []byte{0, 0}
		_, err := parseEcdsaSignaturePlain(zeroSig)
		if err == nil {
			t.Errorf("expected error for 0 values")
		}
	})

}

// TestParseEcdsaSignatureDER tests the parseEcdsaSignatureDER function
func TestParseEcdsaSignatureDER(t *testing.T) {
	curve := elliptic.P256()

	// Generate a valid signature
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	hash := cryptoutils.CryptoHash(crypto.SHA256, []byte("test data"))
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	t.Run("valid DER format", func(t *testing.T) {
		derSig, err := encodeDERSignature(r, s)
		if err != nil {
			t.Fatalf("DER encode: %v", err)
		}
		sig, err := parseEcdsaSignatureDER(derSig)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if sig.R.Cmp(r) != 0 {
			t.Errorf("R mismatch: got %v, want %v", sig.R, r)
		}
		if sig.S.Cmp(s) != 0 {
			t.Errorf("S mismatch: got %v, want %v", sig.S, s)
		}
	})

	t.Run("empty signature", func(t *testing.T) {
		_, err := parseEcdsaSignatureDER([]byte{})
		if err == nil {
			t.Error("expected error for empty signature")
		}
	})

	t.Run("invalid DER", func(t *testing.T) {
		invalidDer := []byte{0x30, 0x05, 0x01, 0x02, 0x03}
		_, err := parseEcdsaSignatureDER(invalidDer)
		if err == nil {
			t.Error("expected error for invalid DER")
		}
	})

	t.Run("DER with remaining data - no error expected", func(t *testing.T) {
		invalidDer := []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x03, 0x03, 0x02, 0x01, 0x01}
		_, err := parseEcdsaSignatureDER(invalidDer)
		if err != nil {
			t.Errorf("expected error for invalid DER: %s", err)
		}
	})

	t.Run("invalid 0 values", func(t *testing.T) {
		invalidDer := []byte{0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00}
		_, err := parseEcdsaSignatureDER(invalidDer)
		if err == nil {
			t.Errorf("expected error for 0 values")
		}
	})
}

func TestValidateActiveAuthSignatureRsaEmptyAuthRspBytes(t *testing.T) {
	var dg15bytes []byte = utils.HexToBytes("6f8201023081ff300d06092a864886f70d01010105000381ed003081e90281e100bb8f93f4dc95e205cda17c6927ab1e365b13065d03cd12e0fce95d96840529453202f56cc4c13f77cd062930c8bc89a2873b257045c286e601cf3c09323a53103314902804aa10a314628ce222206a8866946a36b442041bb54ac81e6855dd1d6e16101833d65a191c20ac8b33b8a1a32920f46043f8031cf2bc17417030865fc5be5a39dee423bcba3ca8177168eb23cfe01ba43ec87711b1cfff85db46f300dd8ae317b50d543b573e119e23af7070d0b2fed6a3b2313a5ec02a531aaed1741f4390d1013e2a0f081eac5dc8b0a1b2c6bdb1206f08d30e3643e1e5bdf536110203010001")
	// NB empty authRspBytes to trigger RSA decrypt error
	var authRspBytes []byte
	var rndIfd []byte = utils.HexToBytes("96302b0f3d7e7864")

	dg15, err := document.NewDG15(dg15bytes)
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}

	_, err = ValidateActiveAuthSignature(dg15, authRspBytes, rndIfd)
	if err == nil {
		t.Fatalf("Expected error")
	}
}

func TestEcdsaSignatureIsWellFormed(t *testing.T) {
	tests := []struct {
		name string
		sig  EcdsaSignature
		want bool
	}{
		{
			name: "valid signature",
			sig: EcdsaSignature{
				R: big.NewInt(1),
				S: big.NewInt(1),
			},
			want: true,
		},
		{
			name: "nil R",
			sig: EcdsaSignature{
				R: nil,
				S: big.NewInt(1),
			},
			want: false,
		},
		{
			name: "nil S",
			sig: EcdsaSignature{
				R: big.NewInt(1),
				S: nil,
			},
			want: false,
		},
		{
			name: "R is zero",
			sig: EcdsaSignature{
				R: big.NewInt(0),
				S: big.NewInt(1),
			},
			want: false,
		},
		{
			name: "S is zero",
			sig: EcdsaSignature{
				R: big.NewInt(1),
				S: big.NewInt(0),
			},
			want: false,
		},
		{
			name: "R is negative",
			sig: EcdsaSignature{
				R: big.NewInt(-1),
				S: big.NewInt(1),
			},
			want: false,
		},
		{
			name: "S is negative",
			sig: EcdsaSignature{
				R: big.NewInt(1),
				S: big.NewInt(-1),
			},
			want: false,
		},
		{
			name: "both nil",
			sig: EcdsaSignature{
				R: nil,
				S: nil,
			},
			want: false,
		},
		{
			name: "both zero",
			sig: EcdsaSignature{
				R: big.NewInt(0),
				S: big.NewInt(0),
			},
			want: false,
		},
		{
			name: "large valid values",
			sig: EcdsaSignature{
				R: new(big.Int).SetBytes(make([]byte, 32)),
				S: big.NewInt(123456789),
			},
			want: false, // R == 0 because bytes are all zero
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.sig.isWellFormed()
			if got != tt.want {
				t.Errorf("validate() = %v, want %v", got, tt.want)
			}
		})
	}
}
