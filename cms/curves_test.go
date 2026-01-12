package cms

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/osanderson/brainpool"
)

func TestGetCurveName(t *testing.T) {
	testCases := []struct {
		curve    elliptic.Curve
		expected string
	}{
		{elliptic.P224(), "P-224"},
		{elliptic.P256(), "P-256"},
		{elliptic.P384(), "P-384"},
		{elliptic.P521(), "P-521"},
		{brainpool.P192r1(), "BrainpoolP192r1"},
		{brainpool.P224r1(), "BrainpoolP224r1"},
		{brainpool.P256r1(), "BrainpoolP256r1"},
		{brainpool.P320r1(), "BrainpoolP320r1"},
		{brainpool.P384r1(), "BrainpoolP384r1"},
		{brainpool.P512r1(), "BrainpoolP512r1"},
	}

	for _, tc := range testCases {
		result := getCurveName(tc.curve)
		if result != tc.expected {
			t.Errorf("getCurveName failed: expected %s, got %s", tc.expected, result)
		}
	}
}

func TestParseEcdsaSignature(t *testing.T) {
	// Valid ECDSA signature from LTU passport logs
	validSig := []byte{
		0x30, 0x3e, // SEQUENCE, length 62
		0x02, 0x1d, 0x00, // INTEGER, length 29
		0xf4, 0x55, 0x24, 0x6c, 0xa1, 0x7c, 0x5e, 0x78,
		0x17, 0x47, 0x86, 0x3e, 0xbc, 0xc3, 0xde, 0x01,
		0xf9, 0xf3, 0x09, 0xde, 0x06, 0x56, 0x75, 0xb5,
		0x3f, 0x13, 0x85, 0x9e,
		0x02, 0x1d, 0x00, // INTEGER, length 29
		0x8e, 0x15, 0x38, 0xe9, 0xa8, 0x14, 0x10, 0xaf,
		0xa6, 0x67, 0xce, 0x45, 0xc5, 0x80, 0x7a, 0xb2,
		0x6f, 0x78, 0x91, 0x41, 0x17, 0xa6, 0xd4, 0x21,
		0x87, 0x2e, 0x31, 0x1d,
	}

	r, s, err := parseEcdsaSignature(validSig)
	if err != nil {
		t.Errorf("parseEcdsaSignature failed on valid signature: %s", err)
	}

	expectedR := new(big.Int).SetBytes([]byte{
		0xf4, 0x55, 0x24, 0x6c, 0xa1, 0x7c, 0x5e, 0x78,
		0x17, 0x47, 0x86, 0x3e, 0xbc, 0xc3, 0xde, 0x01,
		0xf9, 0xf3, 0x09, 0xde, 0x06, 0x56, 0x75, 0xb5,
		0x3f, 0x13, 0x85, 0x9e,
	})
	expectedS := new(big.Int).SetBytes([]byte{
		0x8e, 0x15, 0x38, 0xe9, 0xa8, 0x14, 0x10, 0xaf,
		0xa6, 0x67, 0xce, 0x45, 0xc5, 0x80, 0x7a, 0xb2,
		0x6f, 0x78, 0x91, 0x41, 0x17, 0xa6, 0xd4, 0x21,
		0x87, 0x2e, 0x31, 0x1d,
	})

	if r.Cmp(expectedR) != 0 {
		t.Errorf("parseEcdsaSignature R value mismatch: expected %x, got %x", expectedR, r)
	}
	if s.Cmp(expectedS) != 0 {
		t.Errorf("parseEcdsaSignature S value mismatch: expected %x, got %x", expectedS, s)
	}

	// Test invalid signature
	invalidSig := []byte{0x30, 0x01, 0x02} // Malformed ASN.1
	_, _, err = parseEcdsaSignature(invalidSig)
	if err == nil {
		t.Errorf("parseEcdsaSignature should fail on invalid signature")
	}
}

func TestGetAlternativeCurves(t *testing.T) {
	testCases := []struct {
		curve             elliptic.Curve
		expectedCount     int
		expectedBitLength int
	}{
		{cryptoutils.EllipticP192(), 1, 192}, // Should return BrainpoolP192r1
		{brainpool.P192r1(), 1, 192},         // Should return P-192
		{elliptic.P224(), 1, 224},            // Should return BrainpoolP224r1
		{brainpool.P224r1(), 1, 224},         // Should return P-224
		{elliptic.P256(), 1, 256},            // Should return BrainpoolP256r1
		{brainpool.P256r1(), 1, 256},         // Should return P-256
		{brainpool.P320r1(), 0, 320},         // No alternatives for 320-bit
		{elliptic.P384(), 1, 384},            // Should return BrainpoolP384r1
		{brainpool.P384r1(), 1, 384},         // Should return P-384
		{brainpool.P512r1(), 0, 512},         // No alternatives for 512-bit
		{elliptic.P521(), 0, 521},            // No alternatives for 521-bit
	}

	for _, tc := range testCases {
		alternatives := getAlternativeCurves(tc.curve)
		if len(alternatives) != tc.expectedCount {
			t.Errorf("getAlternativeCurves for %s: expected %d alternatives, got %d",
				getCurveName(tc.curve), tc.expectedCount, len(alternatives))
		}

		// Verify all alternatives have the same bit length
		for _, alt := range alternatives {
			if alt.Params().N.BitLen() != tc.expectedBitLength {
				t.Errorf("getAlternativeCurves returned curve with wrong bit length: expected %d, got %d",
					tc.expectedBitLength, alt.Params().N.BitLen())
			}
		}

		// Verify the original curve is not in alternatives
		for _, alt := range alternatives {
			if alt.Params().N.Cmp(tc.curve.Params().N) == 0 {
				t.Errorf("getAlternativeCurves should not include the original curve")
			}
		}
	}
}

func TestLTUPassportScenario(t *testing.T) {
	// This test verifies the specific LTU passport bug scenario
	// R value from logs: f455246ca17c5e781747863ebcc3de01f9f309de065675b53f13859e

	r := new(big.Int)
	r.SetString("f455246ca17c5e781747863ebcc3de01f9f309de065675b53f13859e", 16)

	// BrainpoolP224r1 order (from documentation)
	brainpoolOrder := brainpool.P224r1().Params().N

	// P-224 order
	p224Order := elliptic.P224().Params().N

	// Verify R exceeds BrainpoolP224r1 order
	if r.Cmp(brainpoolOrder) < 0 {
		t.Errorf("Test setup error: R should exceed BrainpoolP224r1 order")
	}

	// Verify R is within P-224 order
	if r.Cmp(p224Order) >= 0 {
		t.Errorf("Test setup error: R should be within P-224 order")
	}

	t.Logf("R value: %x", r)
	t.Logf("BrainpoolP224r1 order: %x", brainpoolOrder)
	t.Logf("P-224 order: %x", p224Order)
	t.Logf("R < BrainpoolP224r1 order: %v (should be false)", r.Cmp(brainpoolOrder) < 0)
	t.Logf("R < P-224 order: %v (should be true)", r.Cmp(p224Order) < 0)
}

func TestSignatureRangeCheck(t *testing.T) {
	testCases := []struct {
		name      string
		curve     elliptic.Curve
		r         string // hex string
		s         string // hex string
		rExpected bool   // true if R should be in range
		sExpected bool   // true if S should be in range
	}{
		{
			name:      "Valid signature for P-224",
			curve:     elliptic.P224(),
			r:         "3ade5c0624a5677ed7b6450d9420bbe028d499c23be9ef9d8b8a8a04",
			s:         "617d6af141efd0c800c9ba3382c2faf758540a5dd98d1756a1dad981",
			rExpected: true,
			sExpected: true,
		},
		{
			name:      "LTU passport R value with BrainpoolP224r1",
			curve:     brainpool.P224r1(),
			r:         "f455246ca17c5e781747863ebcc3de01f9f309de065675b53f13859e",
			s:         "8e1538e9a81410afa667ce45c5807ab26f78914117a6d421872e311d",
			rExpected: false, // R exceeds BrainpoolP224r1 order
			sExpected: true,
		},
		{
			name:      "LTU passport R value with P-224",
			curve:     elliptic.P224(),
			r:         "f455246ca17c5e781747863ebcc3de01f9f309de065675b53f13859e",
			s:         "8e1538e9a81410afa667ce45c5807ab26f78914117a6d421872e311d",
			rExpected: true, // R is valid for P-224
			sExpected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := new(big.Int)
			r.SetString(tc.r, 16)
			s := new(big.Int)
			s.SetString(tc.s, 16)

			curveOrder := tc.curve.Params().N

			rInRange := r.Cmp(curveOrder) < 0 && r.Sign() > 0
			sInRange := s.Cmp(curveOrder) < 0 && s.Sign() > 0

			if rInRange != tc.rExpected {
				t.Errorf("R range check failed for %s: expected %v, got %v",
					getCurveName(tc.curve), tc.rExpected, rInRange)
			}
			if sInRange != tc.sExpected {
				t.Errorf("S range check failed for %s: expected %v, got %v",
					getCurveName(tc.curve), tc.sExpected, sInRange)
			}
		})
	}
}
