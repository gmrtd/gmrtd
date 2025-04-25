package cms

import (
	"bytes"
	"fmt"
	"log/slog"

	"github.com/gmrtd/gmrtd/utils"
)

type CertPool struct {
	certificates []Certificate
}

func NewCertPool() *CertPool {
	return &CertPool{}
}

// adds one or more certificates to the CertPool
func (certPool *CertPool) Add(certificates []byte) error {
	var certs []Certificate
	var err error

	certs, err = ParseCertificates(certificates)
	if err != nil {
		return fmt.Errorf("(CertPool.Add) ParseCertificates error: %w", err)
	}

	certPool.certificates = append(certPool.certificates, certs...)

	return nil
}

// TODO - probably needs to be more than just SKI (i.e. country?)
func (certPool *CertPool) GetBySki(ski []byte) []Certificate {
	var matchingCerts []Certificate

	for i := 0; i < len(certPool.certificates); i++ {
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
