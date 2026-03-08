// Package activeauth implements the 'Active Authentication' mechanism for verifying the authenticity of the Contactless IC.
package activeauth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"math/big"

	cms "github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/iso7816"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

// TODO - does this currently make any use of DG14.ActiveAuthInfos? (eg NL passport)
//			- not a big deal, as we currently drive AA primarily from DG15

// ecdsaSignature represents an ASN.1/DER encoded ECDSA signature
type ecdsaSignature struct {
	R, S *big.Int
}

// parseEcdsaSignaturePlain parses an ECDSA signature in plain r||s format
// (TR-03110 "ecdsa-plain" style, used by ICAO 9303 passports)
func parseEcdsaSignaturePlain(sigBytes []byte) (r, s *big.Int, err error) {
	if len(sigBytes) == 0 {
		return nil, nil, fmt.Errorf("empty signature")
	}

	if len(sigBytes)%2 != 0 {
		return nil, nil, fmt.Errorf("plain signature must have even length, got %d", len(sigBytes))
	}

	half := len(sigBytes) / 2
	r = new(big.Int).SetBytes(sigBytes[:half])
	s = new(big.Int).SetBytes(sigBytes[half:])

	return r, s, nil
}

// parseEcdsaSignatureDER parses an ECDSA signature in ASN.1/DER format
// (X9.62 standard, used by some national ID cards like Portuguese Cartão de Cidadão)
func parseEcdsaSignatureDER(sigBytes []byte) (r, s *big.Int, err error) {
	if len(sigBytes) == 0 {
		return nil, nil, fmt.Errorf("empty signature")
	}

	var sig ecdsaSignature
	rest, err := asn1.Unmarshal(sigBytes, &sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse DER-encoded ECDSA signature: %w", err)
	}
	if len(rest) > 0 {
		slog.Debug("parseEcdsaSignatureDER", "trailing_bytes", len(rest))
	}
	if sig.R == nil || sig.S == nil {
		return nil, nil, fmt.Errorf("DER-encoded signature has nil R or S")
	}
	return sig.R, sig.S, nil
}

type ActiveAuth struct {
	randomBytesFn cryptoutils.RandomBytesFn
	nfcSession    **iso7816.NfcSession
	document      **document.Document
}

func NewActiveAuth(nfc *iso7816.NfcSession, doc *document.Document) *ActiveAuth {
	var activeAuth ActiveAuth
	activeAuth.randomBytesFn = cryptoutils.RandomBytes
	activeAuth.nfcSession = &nfc
	activeAuth.document = &doc
	return &activeAuth
}

func decodeF(f []byte) (m1 []byte, d []byte, hashAlg crypto.Hash, err error) {
	var tmpF []byte = bytes.Clone(f)

	slog.Debug("decodeF", "f", utils.BytesToHex(f))

	if len(tmpF) < 4 {
		return nil, nil, 0, fmt.Errorf("(decodeF) must have at least 4 bytes")
	}

	// should start with 0x6A
	if tmpF[0] != 0x6A {
		return nil, nil, 0, fmt.Errorf("(decodeF) must start with 0x6A")
	}
	tmpF = tmpF[1:]

	// detect hash from trailer
	{
		var trailerLen int

		switch tmpF[len(tmpF)-1] {
		case 0xBC:
			// SHA-1
			hashAlg = crypto.SHA1
			trailerLen = 1
		case 0xCC:
			// trailer is 2 bytes (i.e. xxCC)
			switch tmpF[len(tmpF)-2] {
			case 0x38:
				hashAlg = crypto.SHA224
			case 0x34:
				hashAlg = crypto.SHA256
			case 0x36:
				hashAlg = crypto.SHA384
			case 0x35:
				hashAlg = crypto.SHA512
			default:
				return nil, nil, 0, fmt.Errorf("(decodeF) unknown hashAlg for 2-byte trailer (%x,CC)", tmpF[len(tmpF)-2])
			}
			trailerLen = 2
		default:
			return nil, nil, 0, fmt.Errorf("(decodeF) unable to determine hash alg from trailer byte (lastByte:%x)", tmpF[len(tmpF)-1])
		}

		// remove the trailer byte(s)
		tmpF = tmpF[:len(tmpF)-trailerLen]
	}

	var digestSize int = cryptoutils.CryptoHashDigestSize(hashAlg)

	// verify we have enough bytes remaining for the digest
	if len(tmpF) < digestSize {
		return nil, nil, 0, fmt.Errorf("(decodeF) insufficient bytes remaining to extract digest (req:%d) (rem:%d)", digestSize, len(tmpF))
	}

	// extract digest (d) and m1
	d = bytes.Clone(tmpF[len(tmpF)-digestSize:])
	m1 = bytes.Clone(tmpF[:len(tmpF)-digestSize])

	slog.Debug("decodeF", "m1", utils.BytesToHex(m1), "d", utils.BytesToHex(d), "hashAlg", hashAlg)

	return
}

func (activeAuth *ActiveAuth) randomIfd() []byte {
	var rndIfd []byte = activeAuth.randomBytesFn(8) // RND.IFD
	slog.Debug("randomIfd", "rndIfd", utils.BytesToHex(rndIfd))
	return rndIfd
}

// DoActiveAuth performs ICAO 9303 Active Authentication (AA) against the
// eMRTD chip to confirm possession of the private key associated with DG15.
//
// Flow:
//  1. Checks presence of DG15 (AA public key). If missing, returns (nil, nil)
//     to indicate AA is skipped without error.
//  2. Generates a random challenge (RndIFD) and sends it to the chip using the
//     INTERNAL AUTHENTICATE command.
//  3. Validates the returned signature using the public key from DG15.
//  4. Emits debug logs for secure messaging (pre/post) when enabled.
//
// Returns:
//   - ActiveAuthResult on successful AA verification.
//   - A wrapped error if INTERNAL AUTHENTICATE or signature verification fails.
//   - (nil, nil) if AA cannot be performed due to missing DG15.
func (activeAuth *ActiveAuth) DoActiveAuth() (result *document.ActiveAuthResult, err error) {
	// skip if DG15 is missing
	if (*activeAuth.document).Mf.Lds1.Dg15 == nil {
		slog.Debug("DoActiveAuth - skipping AA as DG15 is not present")
		return nil, nil
	}

	if (*activeAuth.nfcSession).SM() != nil {
		slog.Debug("DoActiveAuth", "SM(pre)", (*activeAuth.nfcSession).SM().String())
	}

	var rndIfd []byte = activeAuth.randomIfd()

	var intAuthRspBytes []byte

	intAuthRspBytes, err = (*activeAuth.nfcSession).InternalAuthenticate(rndIfd)
	if err != nil {
		return &document.ActiveAuthResult{Success: false}, fmt.Errorf("[DoActiveAuth] doInternalAuthenticate error: %w", err)
	}

	result, err = ValidateActiveAuthSignature((*activeAuth.document).Mf.Lds1.Dg15, intAuthRspBytes, rndIfd)
	if err != nil {
		return result, fmt.Errorf("[DoActiveAuth] ValidateActiveAuthSignature error: %w", err)
	}

	if (*activeAuth.nfcSession).SM() != nil {
		slog.Debug("DoActiveAuth", "SM(post)", (*activeAuth.nfcSession).SM().String())
	}

	return result, err
}

// - reduces dependency on 'activeAuth', which is not always be setup fully by caller
func ValidateActiveAuthSignature(dg15 *document.DG15, intAuthRspBytes, rndIfd []byte) (result *document.ActiveAuthResult, err error) {
	var errContext string

	var subPubKeyInfo cms.SubjectPublicKeyInfo = cms.Asn1decodeSubjectPublicKeyInfo(dg15.SubjectPublicKeyInfoBytes)

	// setup result - but set success to FALSE (initially)
	result = &document.ActiveAuthResult{Success: false, Algorithm: subPubKeyInfo.Algorithm.Algorithm, Nonce: bytes.Clone(rndIfd), Signature: bytes.Clone(intAuthRspBytes)}

	switch subPubKeyInfo.Algorithm.Algorithm.String() {
	case oid.OidRsaEncryption.String():
		{
			var pubKey *cryptoutils.RsaPublicKey = subPubKeyInfo.RsaPubKey()

			// S = rapdu-data
			s := intAuthRspBytes

			// Add context before decryption for debugging
			keyWidth := (pubKey.N.BitLen() + 7) / 8
			errContext = fmt.Sprintf("sigLen:%d,keyWidth:%d,sig:%x", len(s), keyWidth, s)

			f := cryptoutils.RsaDecryptWithPublicKey(s, *pubKey)

			// Log decrypted data for debugging
			slog.Debug("ValidateActiveAuthSignature", "f_len", len(f), "f", utils.BytesToHex(f))

			// ISO/IEC 9796-2: Strip leading zero bytes before decoding
			// The meaningful signature data starts at 0x6A, any leading zeros are padding
			f = utils.TrimLeadingZeroBytes(f)

			m1, d, hashAlg, err := decodeF(f)
			if err != nil {
				return result, fmt.Errorf("(ValidateActiveAuthSignature) decodeF error: %w (Context:%s)", err, errContext)
			}

			// m is concat of m1 and m2 (rnd-ifd)
			var expD []byte
			{
				m := bytes.Clone(m1)
				m = append(m, rndIfd...)
				expD = cryptoutils.CryptoHash(hashAlg, m)
			}

			// verify the hash
			if !bytes.Equal(d, expD) {
				return result, fmt.Errorf("(ValidateActiveAuthSignature) hash mismatch (exp:%x,act:%x) (Context:%s)", expD, d, errContext)
			}
		}
	case oid.OidEcPublicKey.String():
		{
			/*
				6.1.2.3 ECDSA
				For ECDSA, the plain signature format according to [TR-03111] SHALL be used. Only prime curves with uncompressed
				points SHALL be used. A hash algorithm, whose output length is of the same length or shorter than the length of the
				ECDSA key in use, SHALL be used. Only SHA-224, SHA-256, SHA-384 or SHA-512 are supported as hash functions.
				RIPEMD-160 and SHA-1 SHALL NOT be used.
				The message M to be signed is the nonce RND.IFD provided by the Inspection System.

				Note: While ICAO 9303 specifies plain r||s format, some national ID cards (e.g., Portuguese Cartão de Cidadão)
				use ASN.1/DER encoded signatures (X9.62 standard). This implementation tries plain format first, then falls
				back to DER if plain fails and the signature starts with 0x30 (SEQUENCE tag).
			*/
			curve, ecPoint, err := subPubKeyInfo.EcCurveAndPubKey()
			if err != nil {
				return result, fmt.Errorf("(ValidateActiveAuthSignature) EcCurveAndPubKey error: %w (Context:%s)", err, errContext)
			}

			pub := &ecdsa.PublicKey{
				Curve: *curve,
				X:     ecPoint.X,
				Y:     ecPoint.Y,
			}

			var alg = cryptoutils.CryptoHashFromEcPubKey(pub)
			var hash = cryptoutils.CryptoHash(alg, rndIfd)

			// Try plain r||s format first (TR-03110, used by most passports)
			r, s, plainErr := parseEcdsaSignaturePlain(intAuthRspBytes)
			if plainErr == nil {
				slog.Debug("ValidateActiveAuthSignature", "format", "plain r||s")
				if ecdsa.Verify(pub, hash, r, s) {
					// Success with plain format
					result.Success = true
					return result, nil
				}
			}

			// If plain format failed or didn't verify, and signature starts with 0x30, try DER format
			if len(intAuthRspBytes) > 0 && intAuthRspBytes[0] == 0x30 {
				slog.Debug("ValidateActiveAuthSignature", "format", "trying DER/ASN.1 fallback")
				r, s, derErr := parseEcdsaSignatureDER(intAuthRspBytes)
				if derErr == nil {
					if ecdsa.Verify(pub, hash, r, s) {
						// Success with DER format
						slog.Debug("ValidateActiveAuthSignature", "format", "DER/ASN.1 succeeded")
						result.Success = true
						return result, nil
					}
				}
			}

			// Both formats failed
			return result, fmt.Errorf("(ValidateActiveAuthSignature) AA signature did not verify with hash: %s for the provided nonce (tried plain r||s and DER formats)", alg.String())
		}
	default:
		return result, fmt.Errorf("(ValidateActiveAuthSignature) unsupported SubjectPublicKeyInfo (OID:%s) (Context:%s)", subPubKeyInfo.Algorithm.Algorithm.String(), errContext)
	}

	// update result to indicate SUCCESS
	result.Success = true

	return result, err
}
