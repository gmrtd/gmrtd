package pace

import (
	"math"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
)

func TestStandardisedDomainParams(t *testing.T) {
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
		var domainParams *PACEDomainParams = standardisedDomainParams(tc.paramId)

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

func TestStandardisedDomainParamsErr(t *testing.T) {
	// No need to check whether `recover()` is nil. Just turn off the panic.
	defer func() { _ = recover() }()

	// NB error as we're using an invalid paramId
	_ = standardisedDomainParams(-1)

	// Never reaches here if panic
	t.Errorf("expected panic, but didn't get")
}
