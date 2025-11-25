package cms

import (
	"crypto"
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
				ecCurve, ecPoint, err = subPubKeyInfo.GetEcCurveAndPubKey()
				if err != nil {
					return fmt.Errorf("[VerifySignature] GetEcCurveAndPubKey error: %w", err)
				}

				pub = &ecdsa.PublicKey{Curve: *ecCurve, X: ecPoint.X, Y: ecPoint.Y}
			}

			// VerifyASN1: works with non-nist curves (i.e. brainpool) via legacy code (hopefully this doesn't change)
			tmpDigest := truncateHashForEcdsa(digest, pub.Curve)
			validSig := ecdsa.VerifyASN1(pub, tmpDigest, sig)
			slog.Debug("VerifySignature", "validSig", validSig)
			if !validSig {
				slog.Info("VerifySignature (bad ECDSA signature)", "pub.X", utils.BytesToHex(pub.X.Bytes()), "pub.Y", utils.BytesToHex(pub.Y.Bytes()), "digest", utils.BytesToHex(tmpDigest), "signature", utils.BytesToHex(sig))
				return fmt.Errorf("[VerifySignature] Invalid ECDSA signature")
			}

			return nil
		}
	/*
	* RSA-Encryption (PKCS#1 v1.5)
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

			// Convert to crypto/rsa format
			rsaPubKey := &rsa.PublicKey{N: pubKey.N, E: pubKey.E}

			// Get the hash algorithm
			var hashAlg crypto.Hash
			hashAlg, err = cryptoutils.CryptoHashOidToAlg(digestAlg)
			if err != nil {
				return fmt.Errorf("[VerifySignature] CryptoHashOidToAlg error: %w", err)
			}

			// Use proper PKCS#1 v1.5 verification
			// This correctly validates the DigestInfo structure and padding format
			err = rsa.VerifyPKCS1v15(rsaPubKey, hashAlg, digest, sig)
			if err != nil {
				slog.Debug("VerifySignature - RSA PKCS#1 v1.5 signature verification FAILED", "digestAlg", digestAlg.String(), "digest", utils.BytesToHex(digest), "sigAlg", sigAlg.String(), "error", err)
				return fmt.Errorf("[VerifySignature] Invalid RSA PKCS#1 v1.5 signature: %w", err)
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

			var hashAlg crypto.Hash
			hashAlg, err = cryptoutils.CryptoHashOidToAlg(digestAlg)
			if err != nil {
				return fmt.Errorf("[VerifySignature] CryptoHashOidToAlg error: %w", err)
			}

			err = rsa.VerifyPSS(rsaPubKey, hashAlg, digest, sig, nil)
			if err != nil {
				return fmt.Errorf("[VerifySignature] Invalid PSS signature: %w", err)
			}

			return nil
		}
	}

	return fmt.Errorf("[VerifySignature] signature-algorithm not supported: %s", sigAlg.String())
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
