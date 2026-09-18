package iso19794

import "testing"

// FuzzProcessISO19794 fuzzes the ISO/IEC 19794-5 facial-image container parser that
// document.NewDG2 calls directly on the raw biometric data block from the chip
// (dg2.go). Seeded from this package's own real/near-real samples (test1data,
// test2data), plus the DG2-level seeds in document/fuzz_test.go are too shallow to
// ever reach this parser on their own.
func FuzzProcessISO19794(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add(test1data)
	f.Add(test2data)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ProcessISO19794(data)
	})
}
