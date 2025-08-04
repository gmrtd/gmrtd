package cms

import (
	"bytes"
	"fmt"
	"log/slog"

	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

type GenericCertPool struct {
	certificates []Certificate
}

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
func (certPool *GenericCertPool) GetBySKI(ski []byte) []Certificate {
	var matchingCerts []Certificate

	for i := range certPool.certificates {
		var cert *Certificate = &certPool.certificates[i]
		tmpSki := cert.TbsCertificate.Extensions.GetSubjectKeyIdentifier()

		if bytes.Equal(*tmpSki, ski) {
			slog.Debug("CertPool.GetBySki - found matching cert", "Idx", i, "SKI", utils.BytesToHex(ski))
			matchingCerts = append(matchingCerts, *cert)
		}
	}

	if len(matchingCerts) < 1 {
		slog.Debug("CertPool.GetBySki - NO matching certs found", "SKI", utils.BytesToHex(ski))
	}

	return matchingCerts
}

// gets matching certificates by 'issuer' country
func (certPool *GenericCertPool) GetByIssuerCountry(countryAlpha2 string) []Certificate {
	var matchingCerts []Certificate

	for i := range certPool.certificates {
		var cert *Certificate = &certPool.certificates[i]

		tmpCountry := cert.TbsCertificate.GetIssuerRDN().GetByOID(oid.OidCountryName)

		if bytes.Equal(tmpCountry, []byte(countryAlpha2)) {
			slog.Debug("CertPool.GetByIssuerCountry - found matching cert", "Idx", i, "Country", countryAlpha2)
			matchingCerts = append(matchingCerts, *cert)
		}
	}

	if len(matchingCerts) < 1 {
		slog.Debug("CertPool.GetByIssuerCountry - NO matching certs found", "Country", countryAlpha2)
	}

	return matchingCerts
}

func (certPool *GenericCertPool) GetAll() []Certificate {
	var out []Certificate
	out = append(out, certPool.certificates...)
	return out
}

func (certPool GenericCertPool) Count() int {
	return len(certPool.certificates)
}
