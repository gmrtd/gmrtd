package verifier

import (
	"os"
	"sync"
	"testing"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/oid"
	"github.com/gmrtd/gmrtd/utils"
)

// Known-good RSA AA test vectors (from activeauth package tests).
var (
	testDG15Bytes = utils.HexToBytes("6F8201023081FF300D06092A864886F70D01010105000381ED003081E90281E100BB8F93F4DC95E205CDA17C6927AB1E365B13065D03CD12E0FCE95D96840529453202F56CC4C13F77CD062930C8BC89A2873B257045C286E601CF3C09323A53103314902804AA10A314628CE222206A8866946A36B442041BB54AC81E6855DD1D6E16101833D65A191C20AC8B33B8A1A32920F46043F8031CF2BC17417030865FC5BE5A39DEE423BCBA3CA8177168EB23CFE01BA43EC87711B1CFFF85DB46F300DD8AE317B50D543B573E119E23AF7070D0B2FED6A3B2313A5EC02A531AAED1741F4390D1013E2A0F081EAC5DC8B0A1B2C6BDB1206F08D30E3643E1E5BDF536110203010001")
	testAANonce   = utils.HexToBytes("96302b0f3d7e7864")
	testAASig     = utils.HexToBytes("474256306840c0ab1b63c10e1c26bdfef4a0dd843920283cc4e6e70a60f2bd25dc7725f9677bc1cde66379dc28b38e8490f33afb2d10f9980c44c0bfc175d2b6684218f535c92fdd3e18db770a9ccbf91db3c7f0138e6d9e94b9bc8371761e3abed5e5e9b260279cfb238b58ae0d6a01da51c74c2a3ecd62c448bd9f20127f7384587287fa971204234e55b1a856c3e5aaaa620bb799a68fbae08ee132bb61683eba9b0b40dc1e54641cad975b16991cab50af82e3f3985afd19e7427a125f5b4b9878b12a5d2e01c7eedca3bb41c6fc05dccd818bce379d04b1f2f5d43487d3")
)

// buildVerifiableDocWithAA constructs a minimal verifiable blob containing DG15
// and AA evidence with the given nonce and signature.
func buildVerifiableDocWithAA(t *testing.T, nonce, signature []byte) []byte {
	t.Helper()

	var docEx document.DocumentEx

	if err := docEx.Document.NewDG(15, testDG15Bytes); err != nil {
		t.Fatalf("NewDG(15) error: %s", err)
	}

	docEx.Session.ActiveAuthResult = &document.ActiveAuthResult{
		Evidence: &document.ActiveAuthEvidence{
			Algorithm: oid.OidRsaEncryption,
			Nonce:     nonce,
			Signature: signature,
		},
	}

	data, err := docEx.ToCbor()
	if err != nil {
		t.Fatalf("ToCbor error: %s", err)
	}

	return data
}

func emptyVerifier() *Verifier {
	return NewVerifier(&cms.GenericCertPool{})
}

func TestWithAAChallenge(t *testing.T) {
	t.Run("valid 8 bytes", func(t *testing.T) {
		v, err := emptyVerifier().WithAAChallenge(make([]byte, 8))
		if err != nil {
			t.Errorf("unexpected error: %s", err)
		}
		if v == nil {
			t.Errorf("expected non-nil verifier")
		}
	})

	invalidSizes := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"7 bytes", 7},
		{"9 bytes", 9},
		{"16 bytes", 16},
	}
	for _, tc := range invalidSizes {
		t.Run(tc.name, func(t *testing.T) {
			_, err := emptyVerifier().WithAAChallenge(make([]byte, tc.size))
			if err == nil {
				t.Errorf("expected error for challenge of length %d", tc.size)
			}
		})
	}
}

func TestVerifyAANonceMatch(t *testing.T) {
	data := buildVerifiableDocWithAA(t, testAANonce, testAASig)

	v, err := emptyVerifier().WithAAChallenge(testAANonce)
	if err != nil {
		t.Fatalf("WithAAChallenge error: %s", err)
	}

	docEx, err := v.Verify(data)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if docEx.Session.ActiveAuthResult == nil || !docEx.Session.ActiveAuthResult.Success {
		t.Errorf("expected successful AA result")
	}

	if exp := (document.OfflineVerification{AAChallengeBound: true}); docEx.Session.Offline == nil || *docEx.Session.Offline != exp {
		t.Errorf("Session.Offline = %+v, want %+v", docEx.Session.Offline, exp)
	}
}

func TestVerifyAANonceMismatch(t *testing.T) {
	data := buildVerifiableDocWithAA(t, testAANonce, testAASig)

	wrongChallenge := utils.HexToBytes("0000000000000000")

	v, err := emptyVerifier().WithAAChallenge(wrongChallenge)
	if err != nil {
		t.Fatalf("WithAAChallenge error: %s", err)
	}

	_, err = v.Verify(data)
	if err == nil {
		t.Fatalf("expected hard error for AA nonce mismatch")
	}
}

// verifies that Verify() actually runs Document.Verify() and surfaces its
// result via Session.DocumentVerifyErr (previously it didn't - this path
// used to skip the structural/completeness checks that the NFC Reader flow
// enforces via verifyDocument, e.g. mandatory DG1/SOD, or SOD referencing a
// DG that has been stripped from the document).
func TestVerifyDocumentVerifyErrMissingDG1(t *testing.T) {
	var docEx document.DocumentEx

	// NB DG1 deliberately not set - Document.Verify requires it

	data, err := docEx.ToCbor()
	if err != nil {
		t.Fatalf("ToCbor error: %s", err)
	}

	result, err := emptyVerifier().Verify(data)
	if err != nil {
		t.Fatalf("unexpected hard error: %s", err)
	}

	if result.Session.DocumentVerifyErr == nil {
		t.Fatalf("expected DocumentVerifyErr to be set when mandatory DG1/SOD are missing")
	}

	if summary := result.Summary(); summary == nil || summary.DataTrusted {
		t.Errorf("expected DataTrusted to be false when DocumentVerifyErr is set")
	}
}

func TestVerifyNoAAChallenge(t *testing.T) {
	// Without a caller-supplied challenge the verifier should still verify the
	// AA signature cryptographically and record a successful result.
	data := buildVerifiableDocWithAA(t, testAANonce, testAASig)

	docEx, err := emptyVerifier().Verify(data)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if docEx.Session.ActiveAuthResult == nil || !docEx.Session.ActiveAuthResult.Success {
		t.Errorf("expected successful AA result without challenge binding")
	}

	// untrusted by default and not challenge-bound, so this AA must not count towards chip authenticity
	if exp := (document.OfflineVerification{}); docEx.Session.Offline == nil || *docEx.Session.Offline != exp {
		t.Errorf("Session.Offline = %+v, want %+v", docEx.Session.Offline, exp)
	}
}

func TestVerifyWithTrustedSource(t *testing.T) {
	data := buildVerifiableDocWithAA(t, testAANonce, testAASig)

	v, err := emptyVerifier().WithTrustedSource().WithAAChallenge(testAANonce)
	if err != nil {
		t.Fatalf("WithAAChallenge error: %s", err)
	}

	docEx, err := v.Verify(data)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if exp := (document.OfflineVerification{TrustedSource: true, AAChallengeBound: true}); docEx.Session.Offline == nil || *docEx.Session.Offline != exp {
		t.Errorf("Session.Offline = %+v, want %+v", docEx.Session.Offline, exp)
	}
}

// Regression test for a heap-corruption crash observed under concurrent use:
// a shared Verifier's aaChallenge field was written by WithAAChallenge while
// Verify read it from another goroutine, unsynchronised. Run with
// `go test -race` to confirm the mutex added to Verifier closes the race -
// without it, this reliably trips the race detector (and, in production, can
// corrupt the Go heap).
func TestVerifierConcurrentAccess(t *testing.T) {
	v := emptyVerifier()
	data := buildVerifiableDocWithAA(t, testAANonce, testAASig)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = v.WithAAChallenge(make([]byte, 8))
			_, _ = v.Verify(data)
		}()
	}
	wg.Wait()
}

// testdata/GBR-099250692.gmrtd: an expired (Jul 2022) UK passport exported via DocumentEx.ToCbor,
// with EF.COM, SOD, DG1 and DG2 only (no AA/CA/PACE-CAM). Its DG1/SOD/DG2 are also used by the
// document and passiveauth tests. It gives an end-to-end offline verification against the real
// CSCA master list where passive authentication passes. Its UK CSCA expired on 2026-07-24 and has
// since been dropped from the master lists, so it is added to the pool explicitly.
func TestVerifyRealDocumentGBR(t *testing.T) {
	data, err := os.ReadFile("testdata/GBR-099250692.gmrtd")
	if err != nil {
		t.Fatalf("ReadFile error: %s", err)
	}

	pool, err := cms.DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList error: %s", err)
	}

	var ukCsca cms.GenericCertPool
	if err := ukCsca.Add(utils.HexToBytes("308205FA308203E2A0030201020204492EAE16300D06092A864886F70D01010B05003041310B3009060355040613026762310E300C060355040A1305554B4B50413122302006035504031319436F756E747279205369676E696E6720417574686F72697479301E170D3130303332343134303230315A170D3236303732343134333230315A3041310B3009060355040613026762310E300C060355040A1305554B4B50413122302006035504031319436F756E747279205369676E696E6720417574686F7269747930820222300D06092A864886F70D01010105000382020F003082020A0282020100C3583682D60EE9DB5E77F3CD27F02C8657ABA30C70A21EBC33FCAFA8E96B5806A090EF29CDC8A4A286F750C4F237CE89A207D460DED39854CFF2BA8F4E7807C655FE1B60E7459FF7E24DE2806EA6823BA8B3DD0A00C80B3DCB8BAE3C4620D9F5A81E3144E7805C96F147AFB13D6C9BAAB3D469EFCA9EADACAD81ED623FCCA82263D72350F553C17DE29352F937CA3EEFDAA902FE718EFC5F90CE9B35027E5F56CD92FDE396B2ACD2C8A83A7F5712CF7DF298607D072B8E82C5DD94BE323D293ADBD25B4F53467AAAE53E92BDD23E26B5501DA24B53E1F492917CA0FA8C59680FB17C952AC642944639B385A06315C251B204DD922E2F86A1D40F1FE3626E602D8D9ED0870C5D0E86ACB0E3845557E63CBB327D9EFFECD317A31FA337AEAC6F9304EB59B63DFEA4D7EC7AC94891D5D8B14F4FB4DB1AA4A88AD5B339FE7DCB460F8231F5B0628A6EA75C3FC252BF00C0D54D850D489346F3753A476A0EA237CAF9001CE729BB2EC2CEA6368F040A2B1B1108A2133EFFE4CA369D043D58A72D0AC1202138CCA1A370B26D576DA079DBDD6C59989F1E40F670AF27E28231ED3F7A5C7F1F699B9AB217F7125993CDA5C0B25147A0C37D08098B85D8B4F231303B1DF92EFAF03E31D92DE00D6971FD4D43971C318DCCB3F1FE908520F5AA788EADE562D0B23F85FF76340C5D181811B2C19529387807EBDD7C5AB09D971F0D3AB516AD0203010001A381F93081F6300E0603551D0F0101FF04040302010630120603551D130101FF040830060101FF02010030630603551D1F045C305A3058A056A054A4523050310B3009060355040613026762310E300C060355040A1305554B4B50413122302006035504031319436F756E747279205369676E696E6720417574686F72697479310D300B0603550403130443524C31302B0603551D1004243022800F32303130303332343134303230315A810F32303236303732343134333230315A301F0603551D230418301680144531A5B73BCF8BB27C7FAC88C74B4505F6C936B3301D0603551D0E041604144531A5B73BCF8BB27C7FAC88C74B4505F6C936B3300D06092A864886F70D01010B0500038202010054F23F6A723698B06338E7A37FB2C740506E2175970C76E20D629D0AB5557359360826E7A611B3748470C1E7995952547C1BB790F4899D258F9127F6C4730F5FF63A8498EAEB50FAF767283B73325B968B497E8C6361073EC25DA7E4C225F36E5870D5874F11BC102F4DC2FEE784F3B3CB9AF3BD3C55F5A72C1883EB2632153B16F594AA086D549228CF0013199D66899181BE47AC0EF37D5F4FE7CB23B8565CD7F4099968DD90791E8EAAE871914BB25C4ABC5556D8387D4964CD87051088431FC32AAC31E37DCEE14BA835C9618E1365216BD227563D99520FD03B101CA7EABFE326BA71B4DE40DA328B2F65E99B591B01FC132C9713BF525238FEDE68A509653C196AA73404D970509D7112EFBC62F385F9642DDE0FBFC7228E0AB388C69E0304B617CC56E4B6253FBD005B22AFF67420F51069AE8D2DC9E5F076E33016AA4E1BBE11A3B79CBA4E41002021639126B7DDC79DC6DF2CD2C1DDB706B825125514F8E5797C409B1B69A8EADA1E95E1FAD139F7C1E189008A5BAB74DF7E87830AF1FBDFC27BD1985CF8DFE5C631AA4F7C0D439D80FB35B34F7722FC0EFBD2B88B4C4BC918EE4E5BD868EB49E1B6858696B364BCEC7D69E494E7DA8198D69A6ABE1F31D01502F5E78550808C2F14CD447E0E56ACDF01A5A145C52EC867232091F1C71800654CC7529557C3414667F9711275B36E92196DD8D600587D4E93FD08D3")); err != nil {
		t.Fatalf("ukCsca.Add error: %s", err)
	}
	pool.AddCertPool(&ukCsca)

	for _, trusted := range []bool{false, true} {
		v := NewVerifier(pool)
		if trusted {
			v = v.WithTrustedSource()
		}

		docEx, err := v.Verify(data)
		if err != nil {
			t.Fatalf("trusted=%v: unexpected error: %s", trusted, err)
		}

		if docEx.Session.PassiveAuthErr != nil || docEx.Session.DocumentVerifyErr != nil {
			t.Fatalf("trusted=%v: PassiveAuthErr=%v DocumentVerifyErr=%v", trusted, docEx.Session.PassiveAuthErr, docEx.Session.DocumentVerifyErr)
		}

		summary := docEx.Summary()
		if !summary.DataTrusted {
			t.Errorf("trusted=%v: expected DataTrusted", trusted)
		}
		// no AA/CA/PACE-CAM on this document, so trusted data alone can't establish chip authenticity
		if summary.ChipAuthenticity != document.CHIP_AUTH_STATUS_NONE {
			t.Errorf("trusted=%v: ChipAuthenticity = %v, want NONE", trusted, summary.ChipAuthenticity)
		}
		if docEx.Session.Offline == nil || docEx.Session.Offline.TrustedSource != trusted {
			t.Errorf("trusted=%v: Session.Offline = %+v", trusted, docEx.Session.Offline)
		}
		if docEx.Document.Mf.Lds1.Dg1 == nil || docEx.Document.Mf.Lds1.Dg1.Mrz.IssuingState != "GBR" {
			t.Errorf("trusted=%v: expected GBR DG1", trusted)
		}
		assertGbrTrustChain(t, summary.PassiveAuth)
	}
}

// assertGbrTrustChain checks the verified SOD chain of GBR-099250692: a document signer issued by
// the UK CSCA, both expired by now, which must not affect the verified status.
func assertGbrTrustChain(t *testing.T, pa *document.PassiveAuthSummary) {
	t.Helper()
	if pa == nil || pa.Status != document.PASSIVE_AUTH_STATUS_VERIFIED || pa.Sod == nil || !pa.Sod.Verified {
		t.Fatalf("PassiveAuth = %+v, want verified SOD", pa)
	}
	if pa.CardSecurity != nil {
		t.Errorf("CardSecurity = %+v, want nil", pa.CardSecurity)
	}
	if len(pa.Sod.Chain) != 2 {
		t.Fatalf("SOD chain has %d certificates, want 2", len(pa.Sod.Chain))
	}

	dsc, csca := pa.Sod.Chain[0], pa.Sod.Chain[1]
	if dsc.Role != document.CERTIFICATE_ROLE_DOCUMENT_SIGNER || dsc.Subject != "CN=Document Signing Key 35, OU=london, O=ukps, C=gb" {
		t.Errorf("chain[0] = %s %q", dsc.Role, dsc.Subject)
	}
	if csca.Role != document.CERTIFICATE_ROLE_CSCA || csca.Subject != "CN=Country Signing Authority, O=UKKPA, C=gb" {
		t.Errorf("chain[1] = %s %q", csca.Role, csca.Subject)
	}
	if dsc.Issuer != csca.Subject || dsc.AuthorityKeyId != csca.SubjectKeyId {
		t.Errorf("document signer not issued by CSCA: issuer %q AKI %s, CSCA SKI %s", dsc.Issuer, dsc.AuthorityKeyId, csca.SubjectKeyId)
	}
	if dsc.Expired == nil || !*dsc.Expired {
		t.Errorf("expected document signer (valid to 2022-12-01) to be reported expired")
	}
}
