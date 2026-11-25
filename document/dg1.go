package document

import (
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/mrz"
	"github.com/gmrtd/gmrtd/tlv"
)

// DG1Tag is the tag of the DG1 root data object.
const DG1Tag = 0x61

// DG1 is data group 1, the machine readable zone, holding the raw MRZ string and its
// decoded form.
type DG1 struct {
	RawData []byte   `json:"rawData,omitempty"`
	RawMrz  string   `json:"rawMrz,omitempty"`
	Mrz     *mrz.MRZ `json:"mrz,omitempty"`
}

// GetRawData returns the raw DG1 bytes as read from the chip.
func (f *DG1) GetRawData() []byte { return f.RawData }

// NewDG1 parses DG1 and decodes the MRZ it contains (tag 5F1F). It returns nil and no
// error if data is empty, and an error if the TLV is malformed, the root tag or MRZ is
// missing, or the MRZ cannot be decoded.
func NewDG1(data []byte) (dg1 *DG1, err error) {
	if len(data) < 1 {
		return nil, nil
	}

	dg1 = new(DG1)

	dg1.RawData = slices.Clone(data)

	nodes, err := tlv.Decode(dg1.RawData)
	if err != nil {
		return nil, fmt.Errorf("[NewDG1] error: %w", err)
	}

	rootNode := nodes.NodeByTag(DG1Tag)

	if !rootNode.IsValidNode() {
		return nil, fmt.Errorf("root node (%x) missing", DG1Tag)
	}

	{
		mrzBytes := rootNode.NodeByTag(0x5f1f).Value()
		if mrzBytes == nil {
			return nil, fmt.Errorf("MRZ Tag (5F1F) missing")
		}

		dg1.RawMrz = string(mrzBytes)

		dg1.Mrz, err = mrz.MrzDecode(dg1.RawMrz)
		if err != nil {
			return nil, err
		}
	}

	return dg1, nil
}

// IssuingCountryAlpha2 returns the ISO 3166-1 alpha-2 code of the issuing state in the
// MRZ. It returns an error if the MRZ is not set or the issuing state cannot be resolved;
// see ResolveCountry.
func (dg1 DG1) IssuingCountryAlpha2() (string, error) {
	if dg1.Mrz == nil {
		return "", fmt.Errorf("[IssuingCountryAlpha2] MRZ is not set within DG1")
	}

	// NB use Issuing-State to derive the country-code
	info, err := ResolveCountry(dg1.Mrz.IssuingState)
	if err != nil {
		return "", fmt.Errorf("(IssuingCountryAlpha2) %w", err)
	}

	return info.Alpha2, nil
}
