package document

import (
	"fmt"
	"slices"

	"github.com/gmrtd/gmrtd/mrz"
	"github.com/gmrtd/gmrtd/tlv"
)

const DG1Tag = 0x61

type DG1 struct {
	RawData []byte   `json:"rawData,omitempty"`
	RawMrz  string   `json:"rawMrz,omitempty"`
	Mrz     *mrz.MRZ `json:"mrz,omitempty"`
}

func (f *DG1) GetRawData() []byte { return f.RawData }

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
