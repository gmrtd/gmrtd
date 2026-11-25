package cms

import (
	"encoding/asn1"
	"fmt"
	"log/slog"
	"sync"

	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

// SignedDataCertPool is a GenericCertPool populated from a CSCA master list, as created by
// CreateCertPoolFromSignedData.
type SignedDataCertPool struct {
	GenericCertPool // Embedded struct
	lock            sync.Mutex
}

var _ CertPool = (*SignedDataCertPool)(nil)

// CscaMasterList is the ASN.1 CscaMasterList structure carried as the eContent of a CSCA
// master list's SignedData (ICAO Doc 9303 Part 12): a version and a SET of certificates.
type CscaMasterList struct {
	Version int
	Certs   []CscaMasterListCert `asn1:"set"`
}

// CscaMasterListCert holds the raw DER encoding of one certificate in a CscaMasterList.
type CscaMasterListCert struct {
	Cert asn1.RawContent
}

// CreateCertPoolFromSignedData imports an ICAO CSCA master list after verifying
// each master-list signer against the supplied root certificate.
func CreateCertPoolFromSignedData(signedDataBytes, rootCertBytes []byte) (*SignedDataCertPool, error) {
	var out SignedDataCertPool
	var err error

	var signedData *SignedData
	signedData, err = ParseSignedData(signedDataBytes)
	if err != nil {
		return nil, fmt.Errorf("[CreateCertPoolFromSignedData] ParseSignedData error: %w", err)
	}
	if !signedData.Content.EContentType.Equal(oid.OidCscaMasterList) {
		return nil, fmt.Errorf("[CreateCertPoolFromSignedData] expected CSCA master list content type, got %s", signedData.Content.EContentType)
	}

	rootCertPool := &GenericCertPool{}
	err = rootCertPool.Add(rootCertBytes)
	if err != nil {
		return nil, fmt.Errorf("[CreateCertPoolFromSignedData] rootCertPool .add error: %w", err)
	}

	/*
	 * verify the signed data object
	 */
	var certChain [][]byte
	certChain, err = signedData.Verify(rootCertPool)
	if err != nil {
		return nil, fmt.Errorf("[CreateCertPoolFromSignedData] signedData.Verify error: %w", err)
	}
	if len(certChain) < 1 {
		return nil, fmt.Errorf("[CreateCertPoolFromSignedData] empty cert chain")
	}

	// acquire lock (for adding certs)
	out.lock.Lock()
	defer out.lock.Unlock()

	var certs CscaMasterList

	err = utils.ParseAsn1(signedData.Content.EContent, false, &certs)
	if err != nil {
		return nil, fmt.Errorf("[CreateCertPoolFromSignedData] ParseAsn1 error: %w", err)
	}

	slog.Debug("CreateCertPoolFromSignedData", "cert-cnt", len(certs.Certs))

	/*
	* add each of the master-list certs into the cert-pool
	 */
	for i := 0; i < len(certs.Certs); i++ {
		data := certs.Certs[i].Cert
		err = out.Add(data)
		if err != nil {
			return nil, fmt.Errorf("[CreateCertPoolFromSignedData] certPool.Add error: %w", err)
		}
	}

	return &out, nil
}
