package document

// RawDataProvider is implemented by every document file type that stores
// the original card bytes in a RawData field.
type RawDataProvider interface {
	GetRawData() []byte
}

// Compile-time checks that all document file types implement RawDataProvider.
var (
	_ RawDataProvider = (*CardAccess)(nil)
	_ RawDataProvider = (*CardSecurity)(nil)
	_ RawDataProvider = (*EFDIR)(nil)
	_ RawDataProvider = (*COM)(nil)
	_ RawDataProvider = (*SOD)(nil)
	_ RawDataProvider = (*DG1)(nil)
	_ RawDataProvider = (*DG2)(nil)
	_ RawDataProvider = (*DG7)(nil)
	_ RawDataProvider = (*DG11)(nil)
	_ RawDataProvider = (*DG12)(nil)
	_ RawDataProvider = (*DG13)(nil)
	_ RawDataProvider = (*DG14)(nil)
	_ RawDataProvider = (*DG15)(nil)
	_ RawDataProvider = (*DG16)(nil)
)
