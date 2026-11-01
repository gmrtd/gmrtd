package verifier

import (
	"os"
	"testing"

	"github.com/gmrtd/gmrtd/cms"
)

// FuzzVerify drives the whole offline pipeline (CBOR envelope, Document.Verify, Passive
// Authentication, and CA/PACE-CAM/AA evidence replay) from a single untrusted .gmrtd file. The
// GBR seed passes Passive Authentication against the pool, so mutations reach the later stages.
func FuzzVerify(f *testing.F) {
	pool, err := cms.DefaultMasterList()
	if err != nil {
		f.Fatalf("DefaultMasterList error: %s", err)
	}
	pool.AddCertPool(ukCscaPool(f))

	gbr, err := os.ReadFile("testdata/GBR-099250692.gmrtd")
	if err != nil {
		f.Fatalf("ReadFile error: %s", err)
	}

	f.Add(gbr, false)
	f.Add(gbr, true)
	f.Add(buildVerifiableDocWithAA(f, testAANonce, testAASig), false)
	f.Add([]byte(nil), false)

	f.Fuzz(func(t *testing.T, data []byte, trustedSource bool) {
		v := NewVerifier(pool)
		if trustedSource {
			v = v.WithTrustedSource()
		}
		docEx, err := v.Verify(data)
		if err != nil {
			return
		}
		_ = docEx.Summary()
	})
}
