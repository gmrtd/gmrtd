package gmrtd

import (
	"testing"
)

func TestNewDG14NoData(t *testing.T) {
	if dg14, err := NewDG14(nil); dg14 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if dg14, err := NewDG14([]byte{}); dg14 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewDG14(t *testing.T) {
	dg14bytes := HexToBytes("6e82021431820210308201c4060904007f000702020102308201b53082014d06072a8648ce3d020130820140020101303c06072a8648ce3d01010231008cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53306404307bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826043004a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c110461041d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c53150231008cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565020101036200047777b5202c812ea334f4295b6ae711f70cc77ca43a53560569603cb92fb55c084d714bcf291f3c4dbb8ead1278fca88c3d6adebd71f9e2de90cb0450f8ab7cdcba5af6752eb3c57ea7d5f126e21c10cedd0fcb6d7ff2f57a713306e59882b51d300f060a04007f00070202030204020101300d060804007f00070202020201013012060a04007f000702020402040201020201103012060a04007f00070202040604020102020110")

	var dg14 *DG14
	var err error

	if dg14, err = NewDG14(dg14bytes); err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	// TODO - may want to do a deeper verification of the data
	if (len(dg14.SecInfos.PaceInfos) != 2) ||
		(len(dg14.SecInfos.ActiveAuthInfos) != 0) ||
		(len(dg14.SecInfos.ChipAuthInfos) != 1) ||
		(len(dg14.SecInfos.ChipAuthPubKeyInfos) != 1) ||
		(len(dg14.SecInfos.TermAuthInfos) != 1) ||
		(len(dg14.SecInfos.EfDirInfos) != 0) ||
		(len(dg14.SecInfos.UnhandledInfos) != 0) {
		t.Errorf("Unexpected DG14 data")
	}
}

func TestNewDG14UnhappyRootTag(t *testing.T) {
	var dg14bytes []byte = HexToBytes("01021234") // valid TLV but invalid DG14, as tag 6E is missing

	dg14, err := NewDG14(dg14bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg14 != nil {
		t.Errorf("DG14 not expected for error case")
	}
}

func TestNewDG14UnhappyBadSecInfos(t *testing.T) {
	var dg14bytes []byte = HexToBytes("6E03060101") // valid TLV, tag 6E present, but bad SecInfos

	dg14, err := NewDG14(dg14bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg14 != nil {
		t.Errorf("DG14 not expected for error case")
	}
}
