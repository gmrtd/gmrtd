package document

import "testing"

func TestSampleDocument(t *testing.T) {
	doc, err := SampleDocument()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if doc == nil {
		t.Fatal("expected non-nil Document")
	}

	if doc.Mf.Lds1.Com == nil {
		t.Error("expected EF.COM to be present")
	}
	if doc.Mf.Lds1.Sod == nil {
		t.Error("expected EF.SOD to be present")
	}
	if doc.Mf.Lds1.Dg1 == nil {
		t.Error("expected DG1 to be present")
	}
	if doc.Mf.Lds1.Dg2 == nil {
		t.Error("expected DG2 to be present")
	}
	if doc.Mf.Lds1.Dg7 == nil {
		t.Error("expected DG7 to be present")
	}
	if doc.Mf.Lds1.Dg11 == nil {
		t.Error("expected DG11 to be present")
	}
	if doc.Mf.Lds1.Dg12 == nil {
		t.Error("expected DG12 to be present")
	}
	if doc.Mf.Lds1.Dg13 == nil {
		t.Error("expected DG13 to be present")
	}
	if doc.Mf.Lds1.Dg14 == nil {
		t.Error("expected DG14 to be present")
	}
	if doc.Mf.Lds1.Dg15 == nil {
		t.Error("expected DG15 to be present")
	}
	if doc.Mf.Lds1.Dg16 == nil {
		t.Error("expected DG16 to be present")
	}
}
