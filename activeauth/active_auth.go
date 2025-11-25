// Package activeauth implements the 'Active Authentication' mechanism for verifying the authenticity of the Contactless IC.
package activeauth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
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

func (activeAuth *ActiveAuth) doGetRandomIfd() []byte {
	var rndIfd []byte = activeAuth.randomBytesFn(8) // RND.IFD
	slog.Debug("doGetRandomIfd", "rndIfd", utils.BytesToHex(rndIfd))
	return rndIfd
}

func (activeAuth *ActiveAuth) doInternalAuthenticate(rndIfd []byte) (rspBytes []byte, err error) {
	var errContext string

	errContext = fmt.Sprintf("dg15:%x,rndIfd:%x", (*activeAuth.document).Mf.Lds1.Dg15, rndIfd)

	var cApdu *iso7816.CApdu = iso7816.NewCApdu(0, iso7816.INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, rndIfd, (*activeAuth.nfcSession).MaxLe)

	var rApdu *iso7816.RApdu

	rApdu, err = (*activeAuth.nfcSession).DoAPDU(cApdu, "AA Internal Authenticate")
	if err != nil {
		return nil, fmt.Errorf("(doInternalAuthenticate) Internal Authenticate APDU error: %w (Context:%s)", err, errContext)
	}

	errContext = fmt.Sprintf("dg15:%x,rndIfd:%x,rApdu:%s", (*activeAuth.document).Mf.Lds1.Dg15, rndIfd, rApdu.String())

	if !rApdu.IsSuccess() {
		return nil, fmt.Errorf("(doInternalAuthenticate) Internal-Auth failed (rApduStatus:%04x) (Context:%s)", rApdu.Status, errContext)
	}

	slog.Debug("doInternalAuthenticate", "rApdu", rApdu.String())

	rspBytes = bytes.Clone(rApdu.Data)

	return rspBytes, nil
}

func (activeAuth *ActiveAuth) DoActiveAuth() (err error) {

	// skip if we have already performed chip authentication
	if (*activeAuth.document).ChipAuthStatus != document.CHIP_AUTH_STATUS_NONE {
		return nil
	}

	// skip if DG15 is missing
	if (*activeAuth.document).Mf.Lds1.Dg15 == nil {
		slog.Debug("DoActiveAuth - skipping AA as DG15 is not present")
		return nil
	}

	if (*activeAuth.nfcSession).SM != nil {
		slog.Debug("DoActiveAuth", "SM(pre)", (*activeAuth.nfcSession).SM.String())
	}

	var rndIfd []byte = activeAuth.doGetRandomIfd()

	var intAuthRspBytes []byte

	intAuthRspBytes, err = activeAuth.doInternalAuthenticate(rndIfd)
	if err != nil {
		return err
	}

	err = activeAuth.ValidateActiveAuthSignature(intAuthRspBytes, rndIfd)
	if err != nil {
		return err
	}

	if (*activeAuth.nfcSession).SM != nil {
		slog.Debug("DoActiveAuth", "SM(post)", (*activeAuth.nfcSession).SM.String())
	}

	return
}

func (activeAuth *ActiveAuth) ValidateActiveAuthSignature(intAuthRspBytes []byte, rndIfd []byte) error {
	var errContext string

	var subPubKeyInfo cms.SubjectPublicKeyInfo = cms.Asn1decodeSubjectPublicKeyInfo((*activeAuth.document).Mf.Lds1.Dg15.SubjectPublicKeyInfoBytes)

	switch subPubKeyInfo.Algorithm.Algorithm.String() {
	case oid.OidRsaEncryption.String():
		{
			var pubKey *cryptoutils.RsaPublicKey = subPubKeyInfo.GetRsaPubKey()

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
				return fmt.Errorf("(DoActiveAuth) decodeF error: %w (Context:%s)", err, errContext)
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
				return fmt.Errorf("(DoActiveAuth) hash mismatch (exp:%x,act:%x) (Context:%s)", expD, d, errContext)
			}

			// update status to reflect AA was performed
			(*activeAuth.document).ChipAuthStatus = document.CHIP_AUTH_STATUS_AA
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
			*/
			curve, ecPoint, err := subPubKeyInfo.GetEcCurveAndPubKey()
			if err != nil {
				return fmt.Errorf("(ValidateActiveAuthSignature) GetEcCurveAndPubKey error: %w (Context:%s)", err, errContext)
			}

			pub := &ecdsa.PublicKey{
				Curve: *curve,
				X:     ecPoint.X,
				Y:     ecPoint.Y,
			}

			var r, s big.Int
			// Plain concatenation r||s (TR-03110 "ecdsa-plain" style)
			if len(intAuthRspBytes)%2 != 0 {
				return fmt.Errorf("(ValidateActiveAuthSignature) Unexpected plain signature length: %d (Context:%s)", len(intAuthRspBytes), errContext)
			}
			half := len(intAuthRspBytes) / 2
			r.SetBytes(intAuthRspBytes[:half])
			s.SetBytes(intAuthRspBytes[half:])

			var alg = cryptoutils.CryptoHashFromEcPubKey(pub)
			var hash = cryptoutils.CryptoHash(alg, rndIfd)
			var verified = ecdsa.Verify(pub, hash, &r, &s)
			if !verified {
				return fmt.Errorf("(ValidateActiveAuthSignature) AA signature did not verify with hash: %s for the provided nonce", alg.String())
			}
		}
	default:
		return fmt.Errorf("(ValidateActiveAuthSignature) unsupported SubjectPublicKeyInfo (OID:%s) (Context:%s)", subPubKeyInfo.Algorithm.Algorithm.String(), errContext)
	}
	return nil
}
