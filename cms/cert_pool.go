package cms

import (
	"bytes"
	"log"
	"log/slog"

	"github.com/gmrtd/gmrtd/utils"
)

type CertPool struct {
	certificates []Certificate
}

func NewCertPool() *CertPool {
	return &CertPool{}
}

func (certPool *CertPool) Add(data []byte) {
	var cert *Certificate
	var err error

	cert, err = ParseCertificate(data)
	if err != nil {
		log.Panicf("(CertPool.Add) cms.ParseCertificate error: %s", err)
	}

	certPool.certificates = append(certPool.certificates, *cert)
}

// TODO - probably needs to be more than just SKI (i.e. country?)
func (certPool *CertPool) GetBySki(ski []byte) []Certificate {
	var matchingCerts []Certificate

	for i := 0; i < len(certPool.certificates); i++ {
		var cert *Certificate = &certPool.certificates[i]
		tmpSki := cert.TbsCertificate.Extensions.GetSubjectKeyIdentifier()

		if bytes.Equal(*tmpSki, ski) {
			slog.Debug("CertPool.GetBySki - found matching cert", "Idx", i, "SKI", utils.BytesToHex(ski))
			matchingCerts = append(matchingCerts, *cert) // TODO - copy?
		}
	}

	if len(matchingCerts) < 1 {
		slog.Debug("CertPool.GetBySki - NO matching certs found", "SKI", utils.BytesToHex(ski))
	}

	return matchingCerts
}
