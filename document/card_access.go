package document

import (
	"slices"
)

// CardAccess is EF.CardAccess, read from the master file. It holds the SecurityInfos that
// describe the access-control protocols, such as PACE, that the chip supports.
type CardAccess struct {
	RawData       []byte         `json:"rawData,omitempty"`
	SecurityInfos *SecurityInfos `json:"securityInfos,omitempty"`
}

// GetRawData returns the raw EF.CardAccess bytes as read from the chip.
func (f *CardAccess) GetRawData() []byte { return f.RawData }

// NewCardAccess parses EF.CardAccess and decodes its SecurityInfos. It returns nil and no
// error if data is empty, and an error if the SecurityInfos cannot be decoded.
func NewCardAccess(data []byte) (*CardAccess, error) {
	var out CardAccess
	var err error

	if len(data) < 1 {
		return nil, nil
	}

	out.RawData = slices.Clone(data)
	out.SecurityInfos, err = DecodeSecurityInfos(out.RawData)
	if err != nil {
		return nil, err
	}

	return &out, nil
}
