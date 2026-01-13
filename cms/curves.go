package cms

import (
	"crypto/elliptic"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/osanderson/brainpool"
)

// getCurveName returns a human-readable name for the curve
func getCurveName(curve elliptic.Curve) string {
	params := curve.Params()

	// Check NIST curves
	if params.Name != "" {
		return params.Name
	}

	// Check Brainpool curves by comparing the order
	if params.N.Cmp(brainpool.P192r1().Params().N) == 0 {
		return "BrainpoolP192r1"
	}
	if params.N.Cmp(brainpool.P224r1().Params().N) == 0 {
		return "BrainpoolP224r1"
	}
	if params.N.Cmp(brainpool.P256r1().Params().N) == 0 {
		return "BrainpoolP256r1"
	}
	if params.N.Cmp(brainpool.P320r1().Params().N) == 0 {
		return "BrainpoolP320r1"
	}
	if params.N.Cmp(brainpool.P384r1().Params().N) == 0 {
		return "BrainpoolP384r1"
	}
	if params.N.Cmp(brainpool.P512r1().Params().N) == 0 {
		return "BrainpoolP512r1"
	}

	return "Unknown"
}

// getAlternativeCurves returns alternative curves of the same bit length
func getAlternativeCurves(curve elliptic.Curve) []elliptic.Curve {
	bitLen := curve.Params().N.BitLen()
	var alternatives []elliptic.Curve

	switch bitLen {
	case 192:
		// For 192-bit curves, try both P-192 and BrainpoolP192r1
		alternatives = []elliptic.Curve{cryptoutils.EllipticP192(), brainpool.P192r1()}
	case 224:
		// For 224-bit curves, try both P-224 and BrainpoolP224r1
		alternatives = []elliptic.Curve{elliptic.P224(), brainpool.P224r1()}
	case 256:
		// For 256-bit curves, try both P-256 and BrainpoolP256r1
		alternatives = []elliptic.Curve{elliptic.P256(), brainpool.P256r1()}
	case 320:
		// For 320-bit curves, only BrainpoolP320r1 exists
		alternatives = []elliptic.Curve{brainpool.P320r1()}
	case 384:
		// For 384-bit curves, try both P-384 and BrainpoolP384r1
		alternatives = []elliptic.Curve{elliptic.P384(), brainpool.P384r1()}
	case 512:
		// For 512-bit curves, only BrainpoolP512r1 exists
		alternatives = []elliptic.Curve{brainpool.P512r1()}
	case 521:
		// For 521-bit curves, only P-521 exists
		alternatives = []elliptic.Curve{elliptic.P521()}
	}

	// Remove the original curve from alternatives
	var filtered []elliptic.Curve
	for _, alt := range alternatives {
		if alt.Params().N.Cmp(curve.Params().N) != 0 {
			filtered = append(filtered, alt)
		}
	}

	return filtered
}
