package verifier

import (
	"testing"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

// Known-good RSA AA test vectors (from activeauth package tests).
var (
	testDG15Bytes = utils.HexToBytes("6F8201023081FF300D06092A864886F70D01010105000381ED003081E90281E100BB8F93F4DC95E205CDA17C6927AB1E365B13065D03CD12E0FCE95D96840529453202F56CC4C13F77CD062930C8BC89A2873B257045C286E601CF3C09323A53103314902804AA10A314628CE222206A8866946A36B442041BB54AC81E6855DD1D6E16101833D65A191C20AC8B33B8A1A32920F46043F8031CF2BC17417030865FC5BE5A39DEE423BCBA3CA8177168EB23CFE01BA43EC87711B1CFFF85DB46F300DD8AE317B50D543B573E119E23AF7070D0B2FED6A3B2313A5EC02A531AAED1741F4390D1013E2A0F081EAC5DC8B0A1B2C6BDB1206F08D30E3643E1E5BDF536110203010001")
	testAANonce   = utils.HexToBytes("96302b0f3d7e7864")
	testAASig     = utils.HexToBytes("474256306840c0ab1b63c10e1c26bdfef4a0dd843920283cc4e6e70a60f2bd25dc7725f9677bc1cde66379dc28b38e8490f33afb2d10f9980c44c0bfc175d2b6684218f535c92fdd3e18db770a9ccbf91db3c7f0138e6d9e94b9bc8371761e3abed5e5e9b260279cfb238b58ae0d6a01da51c74c2a3ecd62c448bd9f20127f7384587287fa971204234e55b1a856c3e5aaaa620bb799a68fbae08ee132bb61683eba9b0b40dc1e54641cad975b16991cab50af82e3f3985afd19e7427a125f5b4b9878b12a5d2e01c7eedca3bb41c6fc05dccd818bce379d04b1f2f5d43487d3")
)

// buildVerifiableDocWithAA constructs a minimal verifiable blob containing DG15
// and AA evidence with the given nonce and signature.
func buildVerifiableDocWithAA(t *testing.T, nonce, signature []byte) []byte {
	t.Helper()

	var docEx document.DocumentEx

	if err := docEx.Document.NewDG(15, testDG15Bytes); err != nil {
		t.Fatalf("NewDG(15) error: %s", err)
	}

	docEx.Session.ActiveAuthResult = &document.ActiveAuthResult{
		Evidence: &document.ActiveAuthEvidence{
			Algorithm: oid.OidRsaEncryption,
			Nonce:     nonce,
			Signature: signature,
		},
	}

	data, err := docEx.ToCbor()
	if err != nil {
		t.Fatalf("ToCbor error: %s", err)
	}

	return data
}

func emptyVerifier() *Verifier {
	return NewVerifier(&cms.GenericCertPool{})
}

func TestWithAAChallenge(t *testing.T) {
	t.Run("valid 8 bytes", func(t *testing.T) {
		v, err := emptyVerifier().WithAAChallenge(make([]byte, 8))
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if v == nil {
			t.Errorf("expected non-nil verifier")
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
			_, err := emptyVerifier().WithAAChallenge(make([]byte, tc.size))
			if err == nil {
				t.Errorf("expected error for challenge of length %d", tc.size)
			}
		})
	}
}

func TestVerifyAANonceMatch(t *testing.T) {
	data := buildVerifiableDocWithAA(t, testAANonce, testAASig)

	v, err := emptyVerifier().WithAAChallenge(testAANonce)
	if err != nil {
		t.Fatalf("WithAAChallenge error: %s", err)
	}

	docEx, err := v.Verify(data)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if docEx.Session.ActiveAuthResult == nil || !docEx.Session.ActiveAuthResult.Success {
		t.Errorf("expected successful AA result")
	}
}

func TestVerifyAANonceMismatch(t *testing.T) {
	data := buildVerifiableDocWithAA(t, testAANonce, testAASig)

	wrongChallenge := utils.HexToBytes("0000000000000000")

	v, err := emptyVerifier().WithAAChallenge(wrongChallenge)
	if err != nil {
		t.Fatalf("WithAAChallenge error: %s", err)
	}

	_, err = v.Verify(data)
	if err == nil {
		t.Fatalf("expected hard error for AA nonce mismatch")
	}
}

func TestVerifyNoAAChallenge(t *testing.T) {
	// Without a caller-supplied challenge the verifier should still verify the
	// AA signature cryptographically and record a successful result.
	data := buildVerifiableDocWithAA(t, testAANonce, testAASig)

	docEx, err := emptyVerifier().Verify(data)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if docEx.Session.ActiveAuthResult == nil || !docEx.Session.ActiveAuthResult.Success {
		t.Errorf("expected successful AA result without challenge binding")
	}
}
