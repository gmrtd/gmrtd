package cms

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/gmrtd/gmrtd/oid"
)

// CertificateInfo is a display-oriented summary of a Certificate. Fields that cannot be
// determined (e.g. a malformed or missing extension) are left empty rather than failing,
// since certificates are frequently chip-supplied and only partially well-formed.
type CertificateInfo struct {
	Subject            string     `json:"subject,omitempty"`
	Issuer             string     `json:"issuer,omitempty"`
	Country            string     `json:"country,omitempty"` // subject countryName
	SerialNumber       string     `json:"serialNumber,omitempty"`
	NotBefore          *time.Time `json:"notBefore,omitempty"`
	NotAfter           *time.Time `json:"notAfter,omitempty"`
	KeyType            string     `json:"keyType,omitempty"` // e.g. "EC(brainpoolP256r1)", "RSA(3072)"
	SignatureAlgorithm string     `json:"signatureAlgorithm,omitempty"`
	SubjectKeyId       string     `json:"subjectKeyId,omitempty"`
	AuthorityKeyId     string     `json:"authorityKeyId,omitempty"`
	FingerprintSHA256  string     `json:"fingerprintSha256"`
	CA                 bool       `json:"ca"`
}

// Info returns a display-oriented summary of the certificate.
func (cert *Certificate) Info() CertificateInfo {
	info := CertificateInfo{
		KeyType:            cert.KeyType(),
		SignatureAlgorithm: algorithmName(cert.SignatureAlgorithm.Algorithm),
	}

	fingerprint := sha256.Sum256(cert.Raw)
	info.FingerprintSHA256 = fmt.Sprintf("%X", fingerprint)

	if subject, err := cert.TbsCertificate.SubjectRDN(); err == nil {
		info.Subject = subject.String()
		info.Country = string(subject.ByOID(oid.OidCountryName))
	}

	if issuer, err := cert.TbsCertificate.IssuerRDN(); err == nil {
		info.Issuer = issuer.String()
	}

	if serial := cert.TbsCertificate.SerialNumber; serial != nil {
		info.SerialNumber = fmt.Sprintf("%X", serial)
	}

	if notBefore, notAfter, err := cert.TbsCertificate.Validity.Parse(); err == nil {
		info.NotBefore, info.NotAfter = &notBefore, &notAfter
	}

	info.SubjectKeyId = cert.subjectKeyIdHex()
	info.AuthorityKeyId = cert.authorityKeyIdHex()

	if bc, err := cert.TbsCertificate.Extensions.BasicConstraints(); err == nil && bc != nil {
		info.CA = bc.IsCA
	}

	return info
}

// KeyType describes the subject public key, e.g. "EC(brainpoolP256r1)" or "RSA(3072)". It
// returns "" when the key cannot be decoded, and "EC(?)"/"RSA(?)" when only the key family
// is known.
func (cert *Certificate) KeyType() string {
	spki, err := Asn1decodeSubjectPublicKeyInfo(cert.TbsCertificate.SubjectPublicKeyInfo.FullBytes)
	if err != nil {
		return ""
	}

	if spki.IsEC() {
		curve, err := spki.EcCurve()
		if err != nil {
			return "EC(?)"
		}
		return fmt.Sprintf("EC(%s)", GetCurveName(*curve))
	}

	if spki.IsRSA() {
		rsaKey, err := spki.RsaPubKey()
		if err != nil {
			return "RSA(?)"
		}
		return fmt.Sprintf("RSA(%d)", rsaKey.N.BitLen())
	}

	return ""
}

// IsLinkCert reports whether a CA certificate's AKI names a different key than its SKI, i.e.
// it was issued by another CSCA key (a CSCA link certificate) rather than being self-signed.
func (cert *Certificate) IsLinkCert() bool {
	ski, _ := cert.TbsCertificate.Extensions.SubjectKeyIdentifier()
	aki, _ := cert.TbsCertificate.Extensions.AuthorityKeyIdentifier()

	return ski != nil && aki != nil && !bytes.Equal(*ski, aki.KeyIdentifier)
}

func (cert *Certificate) subjectKeyIdHex() string {
	ski, _ := cert.TbsCertificate.Extensions.SubjectKeyIdentifier()
	if ski == nil {
		return ""
	}
	return fmt.Sprintf("%X", []byte(*ski))
}

func (cert *Certificate) authorityKeyIdHex() string {
	aki, _ := cert.TbsCertificate.Extensions.AuthorityKeyIdentifier()
	if aki == nil || len(aki.KeyIdentifier) == 0 {
		return ""
	}
	return fmt.Sprintf("%X", aki.KeyIdentifier)
}

func algorithmName(algorithm asn1.ObjectIdentifier) string {
	if len(algorithm) == 0 {
		return ""
	}
	if name := oid.OidDesc(algorithm); name != "" {
		return name
	}
	return algorithm.String()
}
