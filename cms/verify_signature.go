package cms

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"log/slog"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

func VerifySignature(pubKeyInfo []byte, digestAlg asn1.ObjectIdentifier, digest []byte, sigAlg asn1.ObjectIdentifier, sig []byte) (err error) {
	slog.Debug("VerifySignature", "pubKeyInfo", utils.BytesToHex(pubKeyInfo), "digestAlg", digestAlg.String(), "digest", utils.BytesToHex(digest), "sigAlg", sigAlg.String(), "sig", utils.BytesToHex(sig))

	switch sigAlg.String() {
	/*
	* ECDSA
	 */
	case
		oid.OidEcdsaWithSHA1.String(),
		oid.OidEcdsaWithSHA224.String(),
		oid.OidEcdsaWithSHA256.String(),
		oid.OidEcdsaWithSHA384.String(),
		oid.OidEcdsaWithSHA512.String():
		{
			var pub *ecdsa.PublicKey
			{
				var subPubKeyInfo SubjectPublicKeyInfo = Asn1decodeSubjectPublicKeyInfo(pubKeyInfo)

				var ecCurve *elliptic.Curve
				var ecPoint *cryptoutils.EcPoint
				ecCurve, ecPoint = subPubKeyInfo.GetEcCurveAndPubKey()

				pub = &ecdsa.PublicKey{Curve: *ecCurve, X: ecPoint.X, Y: ecPoint.Y}
			}

			// VerifyASN1: works with non-nist curves (i.e. brainpool) via legacy code (hopefully this doesn't change)
			tmpDigest := truncateHashForEcdsa(digest, pub.Curve)
			validSig := ecdsa.VerifyASN1(pub, tmpDigest, sig)
			slog.Debug("VerifySignature", "validSig", validSig)
			if !validSig {
				slog.Info("VerifySignature (bad ECDSA signature)", "pub.X", utils.BytesToHex(pub.X.Bytes()), "pub.Y", utils.BytesToHex(pub.Y.Bytes()), "digest", utils.BytesToHex(tmpDigest), "signature", utils.BytesToHex(sig))
				return fmt.Errorf("(VerifySignature) Invalid ECDSA signature")
			}

			return nil
		}
	/*
	* RSA-Encryption
	 */
	case
		oid.OidRsaEncryption.String(),
		oid.OidSha1WithRsaEncryption.String(),
		oid.OidSha224WithRSAEncryption.String(),
		oid.OidSha256WithRSAEncryption.String(),
		oid.OidSha384WithRSAEncryption.String(),
		oid.OidSha512WithRSAEncryption.String():
		{
			var pubKey *cryptoutils.RsaPublicKey
			{
				var subPubKeyInfo SubjectPublicKeyInfo = Asn1decodeSubjectPublicKeyInfo(pubKeyInfo)
				pubKey = subPubKeyInfo.GetRsaPubKey()
			}

			sigPlaintext := cryptoutils.RsaDecryptWithPublicKey(sig, *pubKey)

			slog.Debug("VerifySignature", "sig", utils.BytesToHex(sig), "sigPlaintext", utils.BytesToHex(sigPlaintext))

			// verify the 'RSA Encryption' signature (i.e. the decrypted signature ends with the digest)
			// https://cryptobook.nakov.com/digital-signatures/rsa-signatures
			if !bytes.HasSuffix(sigPlaintext, digest) {
				slog.Debug("VerifySignature - RSA Signature verification FAILED")
				return fmt.Errorf("(VerifySignature) Invalid RSA signature (sig:%x, digest:%x)", sigPlaintext, digest)
			}

			return nil
		}
	/*
	* RSA-PSS
	 */
	case oid.OidRsaSsaPss.String():
		{
			var rsaPubKey *rsa.PublicKey
			{
				var subPubKeyInfo SubjectPublicKeyInfo = Asn1decodeSubjectPublicKeyInfo(pubKeyInfo)
				var pubKey *cryptoutils.RsaPublicKey = subPubKeyInfo.GetRsaPubKey()
				rsaPubKey = &rsa.PublicKey{N: pubKey.N, E: pubKey.E}
			}

			err = rsa.VerifyPSS(rsaPubKey, cryptoutils.CryptoHashOidToAlg(digestAlg), digest, sig, nil)
			if err != nil {
				return fmt.Errorf("(VerifySignature) Invalid PSS signature: %w", err)
			}

			return nil
		}
	default:
		return fmt.Errorf("(VerifySignature) signature-algorithm not supported: %s", sigAlg.String())
	}

	return fmt.Errorf("(VerifySignature) unhandled error")
}

// TODO - not sure whether this is even achieving anything?
func truncateHashForEcdsa(hash []byte, curve elliptic.Curve) []byte {
	orderBits := curve.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8

	if len(hash) > orderBytes {
		return hash[:orderBytes]
	}

	return hash
}
