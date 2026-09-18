package iso39794

import "testing"

// FuzzProcessISO39794p5 fuzzes the ISO/IEC 39794-5 facial-image container parser
// that document.NewDG2 calls directly on the raw biometric data block from the chip
// (dg2.go). Seeded from this package's own real/near-real samples.
func FuzzProcessISO39794p5(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0xA1, 0x12, 0x12, 0x34})
	f.Add(allFields39794)
	f.Add(mandFields39794)
	f.Add(mandFields39794_invalidImage)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ProcessISO39794p5(data)
	})
}
