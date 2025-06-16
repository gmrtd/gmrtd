package document

import (
	"testing"

	"github.com/gmrtd/gmrtd/utils"
)

func TestNewDG14NoData(t *testing.T) {
	if dg14, err := NewDG14(nil); dg14 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}

	if dg14, err := NewDG14([]byte{}); dg14 != nil || err != nil {
		t.Errorf("Should be nil when no input data provided")
	}
}

func TestNewDG14BadTlv(t *testing.T) {
	var dg14bytes []byte = utils.HexToBytes("02101234") // invalid TLV encoding - insufficient bytes

	dg14, err := NewDG14(dg14bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg14 != nil {
		t.Errorf("DG not expected for error case")
	}
}

func TestNewDG14UnhappyRootTag(t *testing.T) {
	var dg14bytes []byte = utils.HexToBytes("01021234") // valid TLV but invalid DG14, as tag 6E is missing

	dg14, err := NewDG14(dg14bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg14 != nil {
		t.Errorf("DG14 not expected for error case")
	}
}

func TestNewDG14UnhappyBadSecInfos(t *testing.T) {
	var dg14bytes []byte = utils.HexToBytes("6E03060101") // valid TLV, tag 6E present, but bad SecInfos

	dg14, err := NewDG14(dg14bytes)

	if err == nil {
		t.Errorf("Error expected")
	}

	if dg14 != nil {
		t.Errorf("DG14 not expected for error case")
	}
}

func TestNewDG14(t *testing.T) {
	dg14bytes := utils.HexToBytes("6e82021431820210308201c4060904007f000702020102308201b53082014d06072a8648ce3d020130820140020101303c06072a8648ce3d01010231008cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53306404307bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826043004a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c110461041d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c53150231008cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565020101036200047777b5202c812ea334f4295b6ae711f70cc77ca43a53560569603cb92fb55c084d714bcf291f3c4dbb8ead1278fca88c3d6adebd71f9e2de90cb0450f8ab7cdcba5af6752eb3c57ea7d5f126e21c10cedd0fcb6d7ff2f57a713306e59882b51d300f060a04007f00070202030204020101300d060804007f00070202020201013012060a04007f000702020402040201020201103012060a04007f00070202040604020102020110")

	var doc Document

	err := doc.NewDG(14, dg14bytes)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	var dg14 *DG14 = doc.Mf.Lds1.Dg14

	if (len(dg14.SecInfos.PaceInfos) != 2) ||
		(len(dg14.SecInfos.ChipAuthInfos) != 1) ||
		(len(dg14.SecInfos.ChipAuthPubKeyInfos) != 1) ||
		(len(dg14.SecInfos.TermAuthInfos) != 1) ||
		(dg14.SecInfos.GetTotalCnt() != 5) {
		t.Errorf("Unexpected DG14 data - %+v", dg14.SecInfos)
	}
}

func TestNewDG14AT(t *testing.T) {
	// DG14 from AT passport
	dg14bytes := utils.HexToBytes("6e82017e3182017a300d060804007f0007020202020101300f060a04007f000702020302020201013012060a04007f0007020204020202010202010d30820142060904007f000702020102308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7020101034200041983917269ac877c0b61544c2c022000d2a5aba723e2d80141e648b40911dc3459761f27480e4b57181a53d8fe1190ea86c939ac14363178caffc621f0f905c3")

	var dg14 *DG14
	var err error

	if dg14, err = NewDG14(dg14bytes); err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if (len(dg14.SecInfos.PaceInfos) != 1) ||
		(len(dg14.SecInfos.ChipAuthInfos) != 1) ||
		(len(dg14.SecInfos.ChipAuthPubKeyInfos) != 1) ||
		(len(dg14.SecInfos.TermAuthInfos) != 1) ||
		(dg14.SecInfos.GetTotalCnt() != 4) {
		t.Errorf("Unexpected DG14 data - %+v", dg14.SecInfos)
	}
}

func TestNewDG14MY(t *testing.T) {
	// DG14 from MY passport
	dg14bytes := utils.HexToBytes("6e82016a3182016630820142060904007f000702020102308201333081ec06072a8648ce3d02013081e0020101302c06072a8648ce3d0101022100a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377304404207d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9042026dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b60441048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997022100a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a702010103420004a04f85afdfc316fb5e9f33f94ca45837d20d9d91ad5002307c3f124b6ef5b92565d018a6b7f69db73976bfbb4278757405c64e96104d161649e8a94078eaefce300f060a04007f00070202030201020101300d060804007f0007020202020101")

	var dg14 *DG14
	var err error

	if dg14, err = NewDG14(dg14bytes); err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if (len(dg14.SecInfos.ChipAuthInfos) != 1) ||
		(len(dg14.SecInfos.ChipAuthPubKeyInfos) != 1) ||
		(len(dg14.SecInfos.TermAuthInfos) != 1) ||
		(dg14.SecInfos.GetTotalCnt() != 3) {
		t.Errorf("Unexpected DG14 data - %+v", dg14.SecInfos)
	}
}
