package document

import (
	"errors"
	"testing"
)

func TestGenerateSummaryPassiveAuthSuccess(t *testing.T) {
	docEx := &DocumentEx{
		Session: Session{
			ChipAuthResult:    &ChipAuthResult{Success: true},
			PassiveAuthResult: &PassiveAuthResult{Success: true, Sod: NewPassiveAuth(nil)},
		},
	}

	docEx.GenerateSummary()

	if docEx.Session.Summary == nil {
		t.Fatal("expected Summary to be non-nil")
	}
	if !docEx.Session.Summary.DataTrusted {
		t.Error("expected DataTrusted to be true")
	}
	if docEx.Session.Summary.ChipAuthenticity != CHIP_AUTH_STATUS_CA {
		t.Errorf("expected ChipAuthenticity CA, got %d", docEx.Session.Summary.ChipAuthenticity)
	}
}

func TestGenerateSummaryPassiveAuthFail(t *testing.T) {
	docEx := &DocumentEx{
		Session: Session{
			ChipAuthResult:    &ChipAuthResult{Success: true},
			PassiveAuthResult: &PassiveAuthResult{Success: false},
		},
	}

	docEx.GenerateSummary()

	if docEx.Session.Summary == nil {
		t.Fatal("expected Summary to be non-nil")
	}
	if docEx.Session.Summary.DataTrusted {
		t.Error("expected DataTrusted to be false")
	}
	if docEx.Session.Summary.ChipAuthenticity != CHIP_AUTH_STATUS_NONE {
		t.Errorf("expected ChipAuthenticity NONE, got %d", docEx.Session.Summary.ChipAuthenticity)
	}
}

func TestGenerateSummaryDocumentVerifyErr(t *testing.T) {
	docEx := &DocumentEx{
		Session: Session{
			ChipAuthResult:    &ChipAuthResult{Success: true},
			PassiveAuthResult: &PassiveAuthResult{Success: true, Sod: NewPassiveAuth(nil)},
			DocumentVerifyErr: errors.New("DG14 file missing but referenced by SOD"),
		},
	}

	docEx.GenerateSummary()

	if docEx.Session.Summary == nil {
		t.Fatal("expected Summary to be non-nil")
	}
	if docEx.Session.Summary.DataTrusted {
		t.Error("expected DataTrusted to be false when DocumentVerifyErr is set, even if PassiveAuth succeeded")
	}
}

func TestGenerateSummaryNoPassiveAuth(t *testing.T) {
	docEx := &DocumentEx{
		Session: Session{
			ChipAuthResult: &ChipAuthResult{Success: true},
		},
	}

	docEx.GenerateSummary()

	if docEx.Session.Summary == nil {
		t.Fatal("expected Summary to be non-nil")
	}
	if docEx.Session.Summary.DataTrusted {
		t.Error("expected DataTrusted to be false when no PassiveAuthResult")
	}
	if docEx.Session.Summary.ChipAuthenticity != CHIP_AUTH_STATUS_NONE {
		t.Errorf("expected ChipAuthenticity NONE, got %d", docEx.Session.Summary.ChipAuthenticity)
	}
}

func TestGenerateSummaryEmpty(t *testing.T) {
	docEx := &DocumentEx{}

	docEx.GenerateSummary()

	if docEx.Session.Summary == nil {
		t.Fatal("expected Summary to be non-nil")
	}
	if docEx.Session.Summary.DataTrusted {
		t.Error("expected DataTrusted to be false")
	}
	if docEx.Session.Summary.ChipAuthenticity != CHIP_AUTH_STATUS_NONE {
		t.Errorf("expected ChipAuthenticity NONE, got %d", docEx.Session.Summary.ChipAuthenticity)
	}
}
