package document

import (
	"errors"
	"testing"
)

func TestSummaryPassiveAuthSuccess(t *testing.T) {
	docEx := &DocumentEx{
		Session: Session{
			ChipAuthResult:    &ChipAuthResult{Success: true},
			PassiveAuthResult: &PassiveAuthResult{Success: true, Sod: NewPassiveAuth(nil)},
		},
	}

	summary := docEx.Summary()

	if summary == nil {
		t.Fatal("expected Summary to be non-nil")
	}
	if !summary.DataTrusted {
		t.Error("expected DataTrusted to be true")
	}
	if summary.ChipAuthenticity != CHIP_AUTH_STATUS_CA {
		t.Errorf("expected ChipAuthenticity CA, got %d", summary.ChipAuthenticity)
	}
}

func TestSummaryPassiveAuthFail(t *testing.T) {
	docEx := &DocumentEx{
		Session: Session{
			ChipAuthResult:    &ChipAuthResult{Success: true},
			PassiveAuthResult: &PassiveAuthResult{Success: false},
		},
	}

	summary := docEx.Summary()

	if summary == nil {
		t.Fatal("expected Summary to be non-nil")
	}
	if summary.DataTrusted {
		t.Error("expected DataTrusted to be false")
	}
	if summary.ChipAuthenticity != CHIP_AUTH_STATUS_NONE {
		t.Errorf("expected ChipAuthenticity NONE, got %d", summary.ChipAuthenticity)
	}
}

func TestSummaryDocumentVerifyErr(t *testing.T) {
	docEx := &DocumentEx{
		Session: Session{
			ChipAuthResult:    &ChipAuthResult{Success: true},
			PassiveAuthResult: &PassiveAuthResult{Success: true, Sod: NewPassiveAuth(nil)},
			DocumentVerifyErr: errors.New("DG14 file missing but referenced by SOD"),
		},
	}

	summary := docEx.Summary()

	if summary == nil {
		t.Fatal("expected Summary to be non-nil")
	}
	if summary.DataTrusted {
		t.Error("expected DataTrusted to be false when DocumentVerifyErr is set, even if PassiveAuth succeeded")
	}
}

func TestSummaryNoPassiveAuth(t *testing.T) {
	docEx := &DocumentEx{
		Session: Session{
			ChipAuthResult: &ChipAuthResult{Success: true},
		},
	}

	summary := docEx.Summary()

	if summary == nil {
		t.Fatal("expected Summary to be non-nil")
	}
	if summary.DataTrusted {
		t.Error("expected DataTrusted to be false when no PassiveAuthResult")
	}
	if summary.ChipAuthenticity != CHIP_AUTH_STATUS_NONE {
		t.Errorf("expected ChipAuthenticity NONE, got %d", summary.ChipAuthenticity)
	}
}

func TestSummaryEmpty(t *testing.T) {
	docEx := &DocumentEx{}

	summary := docEx.Summary()

	if summary == nil {
		t.Fatal("expected Summary to be non-nil")
	}
	if summary.DataTrusted {
		t.Error("expected DataTrusted to be false")
	}
	if summary.ChipAuthenticity != CHIP_AUTH_STATUS_NONE {
		t.Errorf("expected ChipAuthenticity NONE, got %d", summary.ChipAuthenticity)
	}
}

func TestSummaryIsComputedFreshNotCached(t *testing.T) {
	docEx := &DocumentEx{}

	if docEx.Summary().DataTrusted {
		t.Fatal("expected DataTrusted to be false before PassiveAuthResult is set")
	}

	docEx.Session.PassiveAuthResult = &PassiveAuthResult{Success: true, Sod: NewPassiveAuth(nil)}

	if !docEx.Summary().DataTrusted {
		t.Error("expected DataTrusted to be true after PassiveAuthResult is set - Summary must reflect current state, not a stale snapshot")
	}
}
