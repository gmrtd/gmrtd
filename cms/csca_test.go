package cms

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"

	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/utils"
)

func TestCscaCertPoolByCountry(t *testing.T) {
	certPool, err := DefaultMasterList()
	if err != nil {
		t.Errorf("CscaCertPool error: %s", err)
	}
	if certPool == nil {
		t.Errorf("missing certPool")
		return
	}

	sgCerts := certPool.ByIssuerCountry("SG")
	if len(sgCerts) < 1 {
		t.Errorf("expected some certs for SG")
	}
}

func TestCscaCertPool(t *testing.T) {

	certPool, err := DefaultMasterList()
	if err != nil {
		t.Errorf("CscaCertPool error: %s", err)
	}
	if certPool == nil {
		t.Errorf("missing certPool")
		return
	}

	var certificates []Certificate = certPool.All()

	// NB no need to recursively verify up the cert chain as we're verifying
	//    each and every certificate in the master-list
	for i := range certificates {
		cert := &certificates[i]

		ski, err := cert.TbsCertificate.Extensions.SubjectKeyIdentifier()
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}

		aki, err := cert.TbsCertificate.Extensions.AuthorityKeyIdentifier()
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}

		digestAlg, err := cert.SignatureAlgorithm.DetermineDigestAlgFromSigAlg()
		if err != nil {
			t.Errorf("(DetermineDigestAlg) unexpected error: %s", err)
			continue
		}

		digest, err := cryptoutils.CryptoHashByOid(*digestAlg, cert.TbsCertificate.Raw)
		if err != nil {
			t.Errorf("(CryptoHashByOid) unexpected error: %s", err)
			continue
		}

		parentCerts := candidateIssuers(cert, aki, certPool, certificates)

		if len(parentCerts) < 1 {
			if isOrphanedCert(*ski) {
				continue
			}
			t.Errorf("0 parent certs - whitelist may need to be updated! (idx:%d, ski:%x)", i, *ski)
			continue
		}

		if !verifySignatureAgainstCerts(parentCerts, *digestAlg, digest, cert.SignatureAlgorithm.Algorithm, cert.SignatureValue.Bytes) {
			t.Errorf("error verifying signature: idx:%1d cnt(parentCerts):%1d, ski:%x, subject:%s, issuer:%s", i, len(parentCerts), *ski, cert.Info().Subject, cert.Info().Issuer)
		}
	}
}

// candidateIssuers returns the certs that may have signed 'cert'. AKI is optional (RFC 5280
// 4.2.1.1 only mandates it for non-self-signed certs, and some CSCA link certs omit it anyway,
// e.g. LV SERIALNUMBER=004 -> 005, EE 01-2016 -> 01-2019), so fall back to issuer DN matching.
func candidateIssuers(cert *Certificate, aki *AuthorityKeyIdentifier, certPool CertPool, all []Certificate) []Certificate {
	if aki != nil {
		return certPool.BySKI(aki.KeyIdentifier)
	}

	var out []Certificate
	for _, c := range all {
		if bytes.Equal(c.TbsCertificate.Subject.FullBytes, cert.TbsCertificate.Issuer.FullBytes) {
			out = append(out, c)
		}
	}
	return out
}

// isOrphanedCert reports whether the cert (by SKI) is a link cert whose issuing CSCA is no
// longer present in the master lists (typically because it has expired and been dropped).
func isOrphanedCert(ski []byte) bool {
	orphans := []string{
		"f5a8f9b1e7a992a0865408db2a471c04a215f4d7",
		"6c17211c20901464d3beb833aa83c538c2a757be",
		"1fe1572e9b35121363a50fee3e2ce2c1d187a8dd",
		"3f38d115cbf5b2016609c464fb6375d812f15acd",
		"2b0f99a34be9d5ae00933a7868cbcd21a6cf47e5",
		"cd3cc520b508a44e6d518dff33fa36cbde108be2",
		"a12ae326fc2b0d76a85c8b4711b9c1c22061c919",
		"9ee0bfdee2d3d4fced1b3928f54aa7b3265dfaf9",
		"db04dae635a2cbecd63f8d60c2060efd5df719e3",
		"76ecb9957793744901c6e392f55327426fa10b50",
		"da62498e35cabec861a39d459fa8a5bd037b729c",
		"91fb674b8082ff4d540c9ab3234b7f0ec85debe3",
		"64389d154eba8000091857847f6f3238ea621bc4",
		"ad4be7657eeaced2e168cd91316f61807f1c91e3",
		// LV link cert (SERIALNUMBER=004 -> 005, no AKI); the 004 CSCA expired 2026-02-12
		"8f7faa0b418d162b202a71fd631acdbd965ff5e8",
	}
	for _, o := range orphans {
		if bytes.Equal(ski, utils.HexToBytes(o)) {
			return true
		}
	}
	return false
}

func verifySignatureAgainstCerts(parentCerts []Certificate, digestAlg asn1.ObjectIdentifier, digest []byte, signatureAlg asn1.ObjectIdentifier, signature []byte) bool {
	// NB we keep processing untl we find a valid parent certificate
	for i := 0; i < len(parentCerts); i++ {
		parentCert := &(parentCerts[i])

		err := VerifySignature(parentCert.TbsCertificate.SubjectPublicKeyInfo.FullBytes, digestAlg, digest, signatureAlg, signature)
		if err == nil {
			return true
		}

		// NB ignore error
	}

	return false
}

func TestDefaultMasterListGermanError(t *testing.T) {
	origGerman := germanMasterListFn
	origDutch := dutchMasterListFn
	origID := indonesian2010SeriesCertsFn
	defer func() {
		germanMasterListFn = origGerman
		dutchMasterListFn = origDutch
		indonesian2010SeriesCertsFn = origID
	}()

	wantErr := errors.New("german boom")

	germanMasterListFn = func() (*SignedDataCertPool, error) {
		return nil, wantErr
	}
	dutchMasterListFn = func() (*SignedDataCertPool, error) {
		t.Fatal("dutchMasterListFn should not be called after german failure")
		return nil, nil
	}
	indonesian2010SeriesCertsFn = func() (*GenericCertPool, error) {
		t.Fatal("indonesian2010SeriesCertsFn should not be called after german failure")
		return nil, nil
	}

	got, err := DefaultMasterList()
	if got != nil {
		t.Fatalf("expected nil result, got %#v", got)
	}
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped error %v, got %v", wantErr, err)
	}
	if !strings.Contains(err.Error(), "[DefaultMasterList] germanMasterListFn error") {
		t.Fatalf("expected context in error, got %q", err.Error())
	}
}

func TestDefaultMasterListDutchError(t *testing.T) {
	origGerman := germanMasterListFn
	origDutch := dutchMasterListFn
	origID := indonesian2010SeriesCertsFn
	defer func() {
		germanMasterListFn = origGerman
		dutchMasterListFn = origDutch
		indonesian2010SeriesCertsFn = origID
	}()

	wantErr := errors.New("dutch boom")
	germanCalled := false

	germanMasterListFn = func() (*SignedDataCertPool, error) {
		germanCalled = true
		return &SignedDataCertPool{}, nil
	}
	dutchMasterListFn = func() (*SignedDataCertPool, error) {
		return nil, wantErr
	}
	indonesian2010SeriesCertsFn = func() (*GenericCertPool, error) {
		t.Fatal("indonesian2010SeriesCertsFn should not be called after dutch failure")
		return nil, nil
	}

	got, err := DefaultMasterList()
	if !germanCalled {
		t.Fatal("expected germanMasterListFn to be called")
	}
	if got != nil {
		t.Fatalf("expected nil result, got %#v", got)
	}
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped error %v, got %v", wantErr, err)
	}
	if !strings.Contains(err.Error(), "[DefaultMasterList] dutchMasterListFn error") {
		t.Fatalf("expected context in error, got %q", err.Error())
	}
}

func TestDefaultMasterListIndonesianError(t *testing.T) {
	origGerman := germanMasterListFn
	origDutch := dutchMasterListFn
	origID := indonesian2010SeriesCertsFn
	defer func() {
		germanMasterListFn = origGerman
		dutchMasterListFn = origDutch
		indonesian2010SeriesCertsFn = origID
	}()

	wantErr := errors.New("indonesian boom")
	germanCalled := false
	dutchCalled := false

	germanMasterListFn = func() (*SignedDataCertPool, error) {
		germanCalled = true
		return &SignedDataCertPool{}, nil
	}
	dutchMasterListFn = func() (*SignedDataCertPool, error) {
		dutchCalled = true
		return &SignedDataCertPool{}, nil
	}
	indonesian2010SeriesCertsFn = func() (*GenericCertPool, error) {
		return nil, wantErr
	}

	got, err := DefaultMasterList()
	if !germanCalled {
		t.Fatal("expected germanMasterListFn to be called")
	}
	if !dutchCalled {
		t.Fatal("expected dutchMasterListFn to be called")
	}
	if got != nil {
		t.Fatalf("expected nil result, got %#v", got)
	}
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped error %v, got %v", wantErr, err)
	}
	if !strings.Contains(err.Error(), "[DefaultMasterList] indonesian2010SeriesCertsFn error") {
		t.Fatalf("expected context in error, got %q", err.Error())
	}
}

func TestGermanMasterListError(t *testing.T) {
	orig := createCertPoolFromSignedDataFn
	defer func() {
		createCertPoolFromSignedDataFn = orig
	}()

	wantErr := errors.New("parse failure")

	createCertPoolFromSignedDataFn = func(data, rootCA []byte) (*SignedDataCertPool, error) {
		if string(data) != string(de_masterList) {
			t.Fatal("expected GermanMasterList to pass de_masterList")
		}
		if string(rootCA) != string(de_masterListRootCA) {
			t.Fatal("expected GermanMasterList to pass de_masterListRootCA")
		}
		return nil, wantErr
	}

	got, err := GermanMasterList()
	if got != nil {
		t.Fatalf("expected nil result, got %#v", got)
	}
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped error %v, got %v", wantErr, err)
	}
}

func TestDutchMasterListError(t *testing.T) {
	orig := createCertPoolFromSignedDataFn
	defer func() {
		createCertPoolFromSignedDataFn = orig
	}()

	wantErr := errors.New("parse failure")

	createCertPoolFromSignedDataFn = func(data, rootCA []byte) (*SignedDataCertPool, error) {
		if string(data) != string(nl_masterList) {
			t.Fatal("expected DutchMasterList to pass nl_masterList")
		}
		if string(rootCA) != string(nl_masterListRootCA) {
			t.Fatal("expected DutchMasterList to pass nl_masterListRootCA")
		}
		return nil, wantErr
	}

	got, err := DutchMasterList()
	if got != nil {
		t.Fatalf("expected nil result, got %#v", got)
	}
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped error %v, got %v", wantErr, err)
	}
}

func TestGenericCertPoolFromCertsFirstCertInvalid(t *testing.T) {
	got, err := genericCertPoolFromCerts([][]byte{
		[]byte("not-a-cert"),
	})

	if got != nil {
		t.Fatalf("expected nil result, got %#v", got)
	}
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "[genericCertPoolFromCerts] certPool.Add(i:0) error") {
		t.Fatalf("expected index/context in error, got %q", err.Error())
	}
}

func TestGenericCertPoolFromCertsSecondCertInvalid(t *testing.T) {
	got, err := genericCertPoolFromCerts([][]byte{
		id_2010series_2010,
		[]byte("not-a-cert"),
	})

	if got != nil {
		t.Fatalf("expected nil result, got %#v", got)
	}
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "[genericCertPoolFromCerts] certPool.Add(i:1) error") {
		t.Fatalf("expected index/context in error, got %q", err.Error())
	}
}
