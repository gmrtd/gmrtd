package cms

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"math/big"
	"strings"

	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

type GenericCertPool struct {
	certificates []Certificate
}

var _ CertPool = (*GenericCertPool)(nil)

// adds one or more certificates to the CertPool
func (certPool *GenericCertPool) Add(certificates []byte) error {
	var certs []Certificate
	var err error

	certs, err = ParseCertificates(certificates)
	if err != nil {
		return fmt.Errorf("[CertPool.Add] ParseCertificates error: %w", err)
	}

	certPool.certificates = append(certPool.certificates, certs...)

	return nil
}

func (certPool *GenericCertPool) AddCerts(certificates []Certificate) {
	certPool.certificates = append(certPool.certificates, certificates...)
}

// gets matching certificates by 'subject' key identifier (ski)
func (certPool *GenericCertPool) BySKI(ski []byte) []Certificate {
	var matchingCerts []Certificate

	for i := range certPool.certificates {
		var cert *Certificate = &certPool.certificates[i]
		tmpSki, err := cert.TbsCertificate.Extensions.SubjectKeyIdentifier()
		if err != nil {
			slog.Warn("SubjectKeyIdentifier error", "error", err)
			continue
		}
		if tmpSki == nil {
			continue
		}

		if bytes.Equal(*tmpSki, ski) {
			slog.Debug("CertPool.BySki - found matching cert", "Idx", i, "SKI", utils.BytesToHex(ski))
			matchingCerts = append(matchingCerts, *cert)
		}
	}

	if len(matchingCerts) < 1 {
		slog.Debug("CertPool.BySki - NO matching certs found", "SKI", utils.BytesToHex(ski))
	}

	return matchingCerts
}

// ByIssuerAndSerial matches certificates by IssuerAndSerialNumber (RFC 5652 §5.3).
// Issuer comparison first tries exact byte match, then falls back to RDN set comparison
// to handle real-world cases where issuers encode RDN attributes in different orderings.
func (certPool *GenericCertPool) ByIssuerAndSerial(raw []byte) ([]Certificate, error) {
	var ias struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}
	if _, err := asn1.Unmarshal(raw, &ias); err != nil {
		return nil, fmt.Errorf("unmarshal IssuerAndSerialNumber: %w", err)
	}

	sidIssuerRDN, err := ParseRDNSequence(ias.Issuer.FullBytes)
	if err != nil {
		return nil, fmt.Errorf("parse SID issuer RDN: %w", err)
	}

	var matchingCerts []Certificate

	for i := range certPool.certificates {
		cert := &certPool.certificates[i]
		if cert.TbsCertificate.SerialNumber.Cmp(ias.SerialNumber) != 0 {
			continue
		}
		if bytes.Equal(cert.TbsCertificate.Issuer.FullBytes, ias.Issuer.FullBytes) {
			slog.Debug("CertPool.ByIssuerAndSerial - exact match", "Idx", i, "Serial", ias.SerialNumber)
			matchingCerts = append(matchingCerts, *cert)
			continue
		}
		certIssuerRDN, err := cert.TbsCertificate.IssuerRDN()
		if err != nil {
			slog.Warn("ByIssuerAndSerial: IssuerRDN error", "error", err)
			continue
		}
		if sidIssuerRDN.Equal(*certIssuerRDN) {
			slog.Debug("CertPool.ByIssuerAndSerial - RDN match (different encoding order)", "Idx", i, "Serial", ias.SerialNumber)
			matchingCerts = append(matchingCerts, *cert)
		}
	}

	if len(matchingCerts) < 1 {
		slog.Debug("CertPool.ByIssuerAndSerial - NO matching certs found", "Serial", ias.SerialNumber)
	}

	return matchingCerts, nil
}

// gets matching certificates by 'issuer' country
func (certPool *GenericCertPool) ByIssuerCountry(countryAlpha2 string) []Certificate {
	var matchingCerts []Certificate

	for i := range certPool.certificates {
		var cert *Certificate = &certPool.certificates[i]

		issuerRdn, err := cert.TbsCertificate.IssuerRDN()
		if err != nil {
			slog.Warn("IssuerRDN error", "error", err)
			continue
		}

		tmpCountry := issuerRdn.ByOID(oid.OidCountryName)

		if strings.EqualFold(string(tmpCountry), countryAlpha2) {
			var sub *SubjectKeyIdentifier
			var err error

			sub, err = cert.TbsCertificate.Extensions.SubjectKeyIdentifier()
			if err != nil {
				slog.Warn("SubjectKeyIdentifier error", "error", err)
				continue
			}

			var skiHex string
			if sub != nil {
				skiHex = utils.BytesToHex(*sub)
			}

			slog.Debug("CertPool.ByIssuerCountry - found matching cert", "Idx", i, "Country", countryAlpha2, "SKI", skiHex)
			matchingCerts = append(matchingCerts, *cert)
		}
	}

	if len(matchingCerts) < 1 {
		slog.Debug("CertPool.ByIssuerCountry - NO matching certs found", "Country", countryAlpha2)
	}

	return matchingCerts
}

func (certPool *GenericCertPool) All() []Certificate {
	var out []Certificate
	out = append(out, certPool.certificates...)
	return out
}

func (certPool GenericCertPool) Count() int {
	return len(certPool.certificates)
}
