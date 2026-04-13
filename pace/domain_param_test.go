package pace

import (
	"errors"
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
			paramId: 8,
			bitSize: 192,
		},
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
		var err error
		var domainParams *DomainParams

		domainParams, err = standardisedDomainParams(tc.paramId)
		if err != nil {
			t.Fatalf("standardisedDomainParams error: %s", err)
		}

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
	testCases := []struct {
		paramId int
		wantErr error
	}{
		{
			paramId: 0,
			wantErr: ErrPACEParamNotImplemented,
		},
		{
			paramId: 1,
			wantErr: ErrPACEParamNotImplemented,
		},
		{
			paramId: 2,
			wantErr: ErrPACEParamNotImplemented,
		},

		{
			paramId: 3,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 4,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 5,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 6,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 7,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 19,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 20,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 21,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 22,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 23,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 24,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 25,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 26,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 27,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 28,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 29,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 30,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 31,
			wantErr: ErrPACEParamRFU,
		},
		{
			paramId: 32,
			wantErr: ErrPACEParamUnsupported,
		},
		{
			paramId: -1,
			wantErr: ErrPACEParamUnsupported,
		},
	}
	for _, tc := range testCases {
		_, err := standardisedDomainParams(tc.paramId)

		if err == nil {
			t.Fatalf("expected error (%v) but got nil", tc.wantErr)
		}

		if !errors.Is(err, tc.wantErr) {
			t.Fatalf("expected error (%v) but got (%v)", tc.wantErr, err)
		}
	}

}
