package pace

import (
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/osanderson/brainpool"
)

type DomainParams struct {
	id     int
	isECDH bool
	ec     elliptic.Curve
}

var (
	ErrPACEParamRFU            = errors.New("PACE parameter is RFU")
	ErrPACEParamNotImplemented = errors.New("PACE parameter is recognised but not implemented")
	ErrPACEParamUnsupported    = errors.New("PACE parameter is unsupported")
)

// ICAO9303 part 11... s9.5.1 Standardized Domain Parameters
func standardisedDomainParams(paramId int) (*DomainParams, error) {
	// NB 3-7 and 19-31 are RFU
	switch paramId {
	case 0, 1, 2:
		// [0] 1024-bit MODP Group with 160-bit Prime Order Subgroup
		// [1] 2048-bit MODP Group with 224-bit Prime Order Subgroup
		// [2] 2048-bit MODP Group with 256-bit Prime Order Subgroup
		return nil, fmt.Errorf("%w: %d", ErrPACEParamNotImplemented, paramId)
	case 3, 4, 5, 6, 7, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31:
		return nil, fmt.Errorf("%w: %d", ErrPACEParamRFU, paramId)
	case 8:
		// NIST P-192 (secp192r1)
		return &DomainParams{
			id:     paramId,
			isECDH: true,
			ec:     cryptoutils.EllipticP192()}, nil
	case 9:
		// Brainpool P192r1
		return &DomainParams{
			id:     paramId,
			isECDH: true,
			ec:     brainpool.P192r1()}, nil
	case 10:
		// NIST P-224 (secp224r1)
		return &DomainParams{
			id:     paramId,
			isECDH: true,
			ec:     elliptic.P224()}, nil
	case 11:
		// Brainpool P224r1
		return &DomainParams{
			id:     paramId,
			isECDH: true,
			ec:     brainpool.P224r1()}, nil
	case 12:
		// NIST P-256 (secp256r1)
		return &DomainParams{
			id:     paramId,
			isECDH: true,
			ec:     elliptic.P256()}, nil
	case 13:
		// Brainpool P256r1
		return &DomainParams{
			id:     paramId,
			isECDH: true,
			ec:     brainpool.P256r1()}, nil
	case 14:
		// Brainpool P320r1
		return &DomainParams{
			id:     paramId,
			isECDH: true,
			ec:     brainpool.P320r1()}, nil
	case 15:
		// NIST P-384 (secp384r1)
		return &DomainParams{
			id:     paramId,
			isECDH: true,
			ec:     elliptic.P384()}, nil
	case 16:
		// Brainpool P384r1
		return &DomainParams{
			id:     paramId,
			isECDH: true,
			ec:     brainpool.P384r1()}, nil
	case 17:
		// Brainpool P512r1
		return &DomainParams{
			id:     paramId,
			isECDH: true,
			ec:     brainpool.P512r1()}, nil
	case 18:
		// NIST P-521 (secp521r1)
		return &DomainParams{
			id:     paramId,
			isECDH: true,
			ec:     elliptic.P521()}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrPACEParamUnsupported, paramId)
	}
}
