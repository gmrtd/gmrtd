package document

import (
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/tlv"
)

// DG15Tag is the tag of the DG15 root data object.
const DG15Tag = 0x6F

// DG15 is data group 15, the Active Authentication public key, kept as the DER-encoded
// SubjectPublicKeyInfo.
type DG15 struct {
	RawData                   []byte `json:"rawData,omitempty"`
	SubjectPublicKeyInfoBytes []byte `json:"subjectPublicKeyInfoBytes,omitempty"`
}

// GetRawData returns the raw DG15 bytes as read from the chip.
func (f *DG15) GetRawData() []byte { return f.RawData }

// NewDG15 extracts the SubjectPublicKeyInfo from DG15; the key itself is not parsed here.
// It returns nil and no error if data is empty, and an error if the root tag cannot be
// unwrapped or its content is empty.
func NewDG15(data []byte) (*DG15, error) {
	var err error

	if len(data) < 1 {
		return nil, nil
	}

	var out *DG15 = new(DG15)

	out.RawData = slices.Clone(data)

	// extract the content from the root tag
	out.SubjectPublicKeyInfoBytes, err = tlv.UnwrapTag(DG15Tag, out.RawData)
	if err != nil {
		return nil, fmt.Errorf("[NewDG15] UnwrapTag error: %w", err)
	}

	if len(out.SubjectPublicKeyInfoBytes) < 1 {
		return nil, fmt.Errorf("[NewDG15] missing SubjectPublicKeyInfo")
	}

	return out, nil
}
