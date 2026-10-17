package document

import (
	"errors"
	"testing"
	"time"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/utils"
)

const sampleDscSubject = "CN=DS-AUSTRIA-eMRTD, SERIALNUMBER=004015, OU=BMI, O=GV, C=AT"

func sampleDocAndDsc(t *testing.T) (*Document, []byte) {
	t.Helper()
	doc, err := SampleDocument()
	if err != nil {
		t.Fatalf("SampleDocument error: %s", err)
	}
	signers, err := doc.Mf.Lds1.Sod.SD.SignerCertificates()
	if err != nil || len(signers) != 1 {
		t.Fatalf("SignerCertificates: signers=%d err=%v", len(signers), err)
	}
	return doc, signers[0].Raw
}

func ukCscaRaw(t *testing.T) []byte {
	t.Helper()
	pool, err := cms.DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList error: %s", err)
	}
	certs := pool.BySKI(utils.HexToBytes("4531A5B73BCF8BB27C7FAC88C74B4505F6C936B3"))
	if len(certs) < 1 {
		t.Fatalf("UK CSCA not found in master list")
	}
	return certs[0].Raw
}

func TestPassiveAuthSummaryNotPerformed(t *testing.T) {
	doc, _ := sampleDocAndDsc(t)

	summary := buildPassiveAuthSummary(doc, &Session{}, time.Now())

	if summary.Status != PASSIVE_AUTH_STATUS_NOT_PERFORMED || summary.Error != "" {
		t.Fatalf("Status = %s, Error = %q", summary.Status, summary.Error)
	}
	assertUnverifiedDsc(t, summary.Sod)
	if summary.CardSecurity != nil {
		t.Errorf("CardSecurity = %+v, want nil (absent)", summary.CardSecurity)
	}
}

func TestPassiveAuthSummaryFailed(t *testing.T) {
	doc, _ := sampleDocAndDsc(t)
	session := &Session{
		PassiveAuthResult: &PassiveAuthResult{Success: false, Sod: &PassiveAuth{}},
		PassiveAuthErr:    errors.New("no CSCA for country"),
	}

	summary := buildPassiveAuthSummary(doc, session, time.Now())

	if summary.Status != PASSIVE_AUTH_STATUS_FAILED || summary.Error != "no CSCA for country" {
		t.Fatalf("Status = %s, Error = %q", summary.Status, summary.Error)
	}
	assertUnverifiedDsc(t, summary.Sod)
}

func assertUnverifiedDsc(t *testing.T, trust *SignedObjectTrust) {
	t.Helper()
	if trust == nil || trust.Verified || len(trust.Chain) != 1 {
		t.Fatalf("SOD trust = %+v, want one unverified certificate", trust)
	}
	if trust.Chain[0].Role != CERTIFICATE_ROLE_DOCUMENT_SIGNER || trust.Chain[0].Subject != sampleDscSubject {
		t.Errorf("chain[0] = %s %q", trust.Chain[0].Role, trust.Chain[0].Subject)
	}
}

func TestPassiveAuthSummaryVerified(t *testing.T) {
	doc, dscRaw := sampleDocAndDsc(t)
	cscaRaw := ukCscaRaw(t)

	// CardSecurity is absent from the sample document, so reuse the SOD's SignedData
	doc.Mf.CardSecurity = &CardSecurity{SD: doc.Mf.Lds1.Sod.SD}

	session := &Session{PassiveAuthResult: &PassiveAuthResult{
		Success: true,
		Sod:     &PassiveAuth{CertChain: [][]byte{dscRaw, cscaRaw, {0xFF}}}, // malformed entries are skipped
		CardSec: &PassiveAuth{CertChain: [][]byte{dscRaw, cscaRaw}},
	}}

	summary := buildPassiveAuthSummary(doc, session, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))

	if summary.Status != PASSIVE_AUTH_STATUS_VERIFIED {
		t.Fatalf("Status = %s", summary.Status)
	}
	for name, trust := range map[string]*SignedObjectTrust{"SOD": summary.Sod, "CardSecurity": summary.CardSecurity} {
		if trust == nil || !trust.Verified || len(trust.Chain) != 2 {
			t.Fatalf("%s trust = %+v, want verified 2-certificate chain", name, trust)
		}
		dsc, csca := trust.Chain[0], trust.Chain[1]
		if dsc.Role != CERTIFICATE_ROLE_DOCUMENT_SIGNER || dsc.Subject != sampleDscSubject {
			t.Errorf("%s chain[0] = %s %q", name, dsc.Role, dsc.Subject)
		}
		if csca.Role != CERTIFICATE_ROLE_CSCA || csca.Country != "gb" {
			t.Errorf("%s chain[1] = %s %q", name, csca.Role, csca.Country)
		}
		// Austrian DSC valid until 2033, UK CSCA until 2026-07-24
		if dsc.Expired == nil || *dsc.Expired || csca.Expired == nil || *csca.Expired {
			t.Errorf("%s: expected neither certificate expired on 2025-01-01", name)
		}
	}

	later := buildPassiveAuthSummary(doc, session, time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	if csca := later.Sod.Chain[1]; csca.Expired == nil || !*csca.Expired {
		t.Errorf("expected UK CSCA expired on 2030-01-01")
	}
}

func TestPassiveAuthSummaryNoSod(t *testing.T) {
	summary := buildPassiveAuthSummary(&Document{}, &Session{}, time.Now())

	if summary.Sod != nil || summary.CardSecurity != nil {
		t.Errorf("summary = %+v, want no signed objects", summary)
	}
}

func TestSignedObjectTrustUnselectableSigner(t *testing.T) {
	sd := &cms.SignedData{SignerInfos: []cms.SignerInfo{{}}}

	if trust := signedObjectTrust(sd, nil, time.Now()); trust.Verified || len(trust.Chain) != 0 {
		t.Errorf("trust = %+v, want empty unverified", trust)
	}
	if trust := signedObjectTrust(nil, nil, time.Now()); trust.Verified || len(trust.Chain) != 0 {
		t.Errorf("trust = %+v, want empty unverified", trust)
	}
}

func TestCertificateRoleLink(t *testing.T) {
	pool, err := cms.DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList error: %s", err)
	}

	// UK CSCA link certificate: SKI DB1D16..., issued by CSCA AD4BE7...
	for _, cert := range pool.BySKI(utils.HexToBytes("DB1D1657C76023089B0139E2613C082134B57CA1")) {
		if cert.IsLinkCert() {
			if got := trustChainCertificate(&cert, time.Now()).Role; got != CERTIFICATE_ROLE_CSCA_LINK {
				t.Errorf("Role = %s, want %s", got, CERTIFICATE_ROLE_CSCA_LINK)
			}
			return
		}
	}
	t.Fatalf("UK link certificate not found in master list")
}

func TestSummaryIncludesPassiveAuth(t *testing.T) {
	doc, _ := sampleDocAndDsc(t)
	docEx := DocumentEx{Document: *doc}

	if pa := docEx.Summary().PassiveAuth; pa == nil || pa.Status != PASSIVE_AUTH_STATUS_NOT_PERFORMED {
		t.Errorf("Summary().PassiveAuth = %+v", pa)
	}
}
