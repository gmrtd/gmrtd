package gmrtd

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"log"
	"log/slog"
	"math/big"
)

type ActiveAuth struct {
	randomBytesFn RandomBytesFn
}

func NewActiveAuth() *ActiveAuth {
	var activeAuth ActiveAuth
	activeAuth.randomBytesFn = RandomBytes
	return &activeAuth
}

func rsaDecryptWithPublicKey(ciphertext []byte, publicKey *rsa.PublicKey) []byte {
	if len(ciphertext) < 1 {
		log.Panicf("ciphertext too short (len:%01d)", len(ciphertext))
	}

	m := new(big.Int).SetBytes(ciphertext)
	e := big.NewInt(int64(publicKey.E))
	c := new(big.Int).Exp(m, e, publicKey.N)

	return c.Bytes()
}

func decodeF(f []byte) (m1 []byte, d []byte, hashAlg crypto.Hash, err error) {
	var tmpF []byte = bytes.Clone(f)

	slog.Debug("decodeF", "f", BytesToHex(f))

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

	var digestSize int = CryptoHashDigestSize(hashAlg)

	// verify we have enough bytes remaining for the digest
	if len(tmpF) < digestSize {
		return nil, nil, 0, fmt.Errorf("(decodeF) insufficient bytes remaining to extract digest (req:%d) (rem:%d)", digestSize, len(tmpF))
	}

	// extract digest (d) and m1
	d = bytes.Clone(tmpF[len(tmpF)-digestSize:])
	m1 = bytes.Clone(tmpF[:len(tmpF)-digestSize])

	slog.Debug("decodeF", "m1", BytesToHex(m1), "d", BytesToHex(d), "hashAlg", hashAlg)

	return
}

func (activeAuth *ActiveAuth) doGetRandomIfd() []byte {
	var rndIfd []byte = activeAuth.randomBytesFn(8) // RND.IFD
	slog.Debug("doGetRandomIfd", "rndIfd", BytesToHex(rndIfd))
	return rndIfd
}

func (activeAuth *ActiveAuth) doInternalAuthenticate(nfc *NfcSession, doc *Document, rndIfd []byte) (rspBytes []byte, err error) {
	var errContext string

	errContext = fmt.Sprintf("dg15:%x,rndIfd:%x", doc.Dg15, rndIfd)

	var cApdu *CApdu = NewCApdu(0, INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, rndIfd, nfc.maxLe)

	var rApdu *RApdu

	rApdu, err = nfc.DoAPDU(cApdu, "AA Internal Authenticate")
	if err != nil {
		return nil, fmt.Errorf("(doInternalAuthenticate) Internal Authenticate APDU error: %w (Context:%s)", err, errContext)
	}
	errContext = fmt.Sprintf("dg15:%x,rndIfd:%x,rApdu:%s", doc.Dg15, rndIfd, rApdu.String())
	if !rApdu.IsSuccess() {
		return nil, fmt.Errorf("(doInternalAuthenticate) Internal-Auth failed (rApduStatus:%04x)", rApdu.Status)
	}

	slog.Debug("doInternalAuthenticate", "rApdu", rApdu.String())

	rspBytes = bytes.Clone(rApdu.Data)

	return rspBytes, nil
}

func (activeAuth *ActiveAuth) doActiveAuth(nfc *NfcSession, doc *Document) (err error) {
	var errContext string

	// skip if we have already performed chip authentication
	if doc.ChipAuthStatus != CHIP_AUTH_STATUS_NONE {
		return nil
	}

	// skip if DG15 is missing
	if doc.Dg15 == nil {
		slog.Debug("doActiveAuth - skipping AA as DG15 is not present")
		return nil
	}

	if nfc.sm != nil {
		slog.Debug("doActiveAuth", "SM(pre)", nfc.sm.String())
	}

	var rndIfd []byte = activeAuth.doGetRandomIfd()

	var intAuthRspBytes []byte

	intAuthRspBytes, err = activeAuth.doInternalAuthenticate(nfc, doc, rndIfd)
	if err != nil {
		return err
	}

	{
		publicKey, err := x509.ParsePKIXPublicKey(doc.Dg15.SubjectPublicKeyInfoBytes)
		if err != nil {
			return fmt.Errorf("(doActiveAuth) Error parsing SubjectPublicKeyInfo: %w (Context:%s)", err, errContext)
		}

		switch publicKey.(type) {
		case *rsa.PublicKey:
			{
				var rsaPubKey *rsa.PublicKey = publicKey.(*rsa.PublicKey)

				// S = rapdu-data
				s := intAuthRspBytes

				f := rsaDecryptWithPublicKey(s, rsaPubKey)

				m1, d, hashAlg, err := decodeF(f)
				if err != nil {
					return fmt.Errorf("(doActiveAuth) decodeF error: %w (Context:%s)", err, errContext)
				}

				// m is concat of m1 and m2 (rnd-ifd)
				var expD []byte
				{
					m := bytes.Clone(m1)
					m = append(m, rndIfd...)
					expD = CryptoHash(hashAlg, m)
				}

				// verify the hash
				if !bytes.Equal(d, expD) {
					return fmt.Errorf("(doActiveAuth) hash mismatch (exp:%x,act:%x) (Context:%s)", expD, d, errContext)
				}

				// update status to reflect AA was performed
				doc.ChipAuthStatus = CHIP_AUTH_STATUS_AA
			}
			// TODO - ECDSA is the only other one we expect (as per ICAO-9303p11), but not supported at present
			/*
				6.1.2.3 ECDSA
				For ECDSA, the plain signature format according to [TR-03111] SHALL be used. Only prime curves with uncompressed
				points SHALL be used. A hash algorithm, whose output length is of the same length or shorter than the length of the
				ECDSA key in use, SHALL be used. Only SHA-224, SHA-256, SHA-384 or SHA-512 are supported as hash functions.
				RIPEMD-160 and SHA-1 SHALL NOT be used.
				The message M to be signed is the nonce RND.IFD provided by the Inspection System.
			*/
		default:
			return fmt.Errorf("(doActiveAuth) unsupported SubjectPublicKeyInfo (Context:%s)", errContext)
		}
	}

	if nfc.sm != nil {
		slog.Debug("doActiveAuth", "SM(post)", nfc.sm.String())
	}

	return
}
