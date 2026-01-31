package document

import (
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/tlv"
)

const DG15Tag = 0x6F

type DG15 struct {
	RawData                   []byte `json:"rawData,omitempty"`
	SubjectPublicKeyInfoBytes []byte `json:"subjectPublicKeyInfoBytes,omitempty"`
}

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
