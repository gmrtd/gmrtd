package document

import (
	"fmt"
	"testing"
	"time"

	"github.com/gmrtd/gmrtd/mrz"
)

// NB all NRICs/MRZs here are fictitious

func TestSgNricCentury(t *testing.T) {
	testCases := []struct {
		nric string
		want string
	}{
		{"S1234567D", "19"},
		{"T0123456G", "20"},
		{"S1234567D ", "19"}, // trailing space left by MRZ filler decoding
		{"S1234567A", ""},    // wrong check letter
		{"T1234567D", ""},    // S check letter with a T prefix
		{"s1234567D", ""},    // lower case
		{"S123456D", ""},     // too short
		{"S12345678D", ""},   // too long
		{"F1234567N", ""},    // FIN (foreigner) - no century encoded
		{"G1234567X", ""},
		{"M1234567K", ""},
		{"", ""},
	}

	for _, tc := range testCases {
		if got := sgNricCentury(tc.nric); got != tc.want {
			t.Errorf("sgNricCentury(%q) = %q, want %q", tc.nric, got, tc.want)
		}
	}
}

func TestIsSgPassport(t *testing.T) {
	testCases := []struct {
		m    *mrz.MRZ
		want bool
	}{
		{&mrz.MRZ{DocumentCode: "P", IssuingState: "SGP", Nationality: "SGP"}, true},
		{&mrz.MRZ{DocumentCode: "PA", IssuingState: "SGP", Nationality: "SGP"}, true},
		{&mrz.MRZ{DocumentCode: "I", IssuingState: "SGP", Nationality: "SGP"}, false},
		{&mrz.MRZ{DocumentCode: "P", IssuingState: "MYS", Nationality: "SGP"}, false},
		{&mrz.MRZ{DocumentCode: "P", IssuingState: "SGP", Nationality: "MYS"}, false},
		{nil, false},
	}

	for i, tc := range testCases {
		if got := isSgPassport(tc.m); got != tc.want {
			t.Errorf("[%d] isSgPassport(%+v) = %v, want %v", i, tc.m, got, tc.want)
		}
	}
}

func sgPassportDoc(dob, optionalData string) *Document {
	doc := &Document{}
	doc.Mf.Lds1.Dg1 = &DG1{Mrz: &mrz.MRZ{
		DocumentCode: "P",
		IssuingState: "SGP",
		Nationality:  "SGP",
		DateOfBirth:  dob,
		OptionalData: optionalData,
	}}
	return doc
}

func TestBuildIdentityAttributesSgPassportDobCenturyFromNric(t *testing.T) {
	testCases := []struct {
		name       string
		doc        *Document
		wantDob    string
		wantSource DateOfBirthSource
	}{
		{"S NRIC -> 19xx", sgPassportDoc("640812", "S1234567D"), "19640812", DOB_SOURCE_DG1_MRZ_SG_NRIC},
		{"T NRIC -> 20xx", sgPassportDoc("010615", "T0123456G"), "20010615", DOB_SOURCE_DG1_MRZ_SG_NRIC},
		{"invalid check letter", sgPassportDoc("640812", "S1234567A"), "640812", DOB_SOURCE_DG1_MRZ},
		{"FIN, not NRIC", sgPassportDoc("640812", "F1234567N"), "640812", DOB_SOURCE_DG1_MRZ},
		{"no optional data", sgPassportDoc("640812", ""), "640812", DOB_SOURCE_DG1_MRZ},
		{"invalid date", sgPassportDoc("641312", "S1234567D"), "641312", DOB_SOURCE_DG1_MRZ},
		{"not an SG passport", func() *Document {
			doc := sgPassportDoc("640812", "S1234567D")
			doc.Mf.Lds1.Dg1.Mrz.IssuingState = "MYS"
			return doc
		}(), "640812", DOB_SOURCE_DG1_MRZ},
		{"DG11 full DOB wins", func() *Document {
			doc := sgPassportDoc("640812", "S1234567D")
			doc.Mf.Lds1.Dg11 = &DG11{Details: PersonDetails{FullDateOfBirth: "19640812"}}
			return doc
		}(), "19640812", DOB_SOURCE_DG11},
	}

	for _, tc := range testCases {
		summary := buildIdentityAttributes(tc.doc)
		if summary.DateOfBirth != tc.wantDob || summary.DateOfBirthSource != tc.wantSource {
			t.Errorf("%s: DateOfBirth = %q (%s), want %q (%s)", tc.name, summary.DateOfBirth, summary.DateOfBirthSource, tc.wantDob, tc.wantSource)
		}
		if summary.DateOfBirthMrzRaw != tc.doc.Mf.Lds1.Dg1.Mrz.DateOfBirth {
			t.Errorf("%s: DateOfBirthMrzRaw = %q, want the untouched MRZ value", tc.name, summary.DateOfBirthMrzRaw)
		}
	}
}

// An inferred full DOB resolves a single Age instead of ambiguous PossibleAges.
func TestBuildIdentityAttributesSgPassportNricGivesSingleAge(t *testing.T) {
	summary := buildIdentityAttributes(sgPassportDoc("640812", "S1234567D"))

	if summary.Age == nil {
		t.Fatalf("Age = nil, want set")
	}
	if want := calculateAge(time.Date(1964, 8, 12, 0, 0, 0, 0, time.UTC), time.Now()); *summary.Age != want {
		t.Errorf("Age = %d, want %d", *summary.Age, want)
	}
	if len(summary.PossibleAges) != 0 {
		t.Errorf("PossibleAges = %v, want empty", summary.PossibleAges)
	}
}

// A 'T' NRIC whose year would put the birth date in the future is rejected, leaving the
// raw MRZ value (no century) in place.
func TestBuildIdentityAttributesSgPassportFutureDobRejected(t *testing.T) {
	futureYY := fmt.Sprintf("%02d", (time.Now().Year()+1)%100)
	summary := buildIdentityAttributes(sgPassportDoc(futureYY+"0101", "T0123456G"))

	if summary.DateOfBirth != futureYY+"0101" || summary.DateOfBirthSource != DOB_SOURCE_DG1_MRZ {
		t.Errorf("DateOfBirth = %q (%s), want the raw MRZ value", summary.DateOfBirth, summary.DateOfBirthSource)
	}
}

// End-to-end from a TD3 MRZ string: the optional data reaches the NRIC check with its
// '<' fillers decoded.
func TestBuildIdentityAttributesSgPassportFromTd3Mrz(t *testing.T) {
	testCases := []struct {
		mrz     string
		wantDob string
	}{
		{"P<SGPTAN<<AH<KOW<<<<<<<<<<<<<<<<<<<<<<<<<<<<E1234567A4SGP6408125M3001019S1234567D<<<<<54", "19640812"},
		{"P<SGPTAN<<AH<KOW<<<<<<<<<<<<<<<<<<<<<<<<<<<<E1234567A4SGP0106153M3001019T0123456G<<<<<02", "20010615"},
		{"P<SGPTAN<<AH<KOW<<<<<<<<<<<<<<<<<<<<<<<<<<<<E1234567A4SGP6408125M3001019S1234567A<<<<<28", "640812"},
	}

	for _, tc := range testCases {
		m, err := mrz.MrzDecode(tc.mrz)
		if err != nil {
			t.Fatalf("MrzDecode error: %s", err)
		}
		doc := &Document{}
		doc.Mf.Lds1.Dg1 = &DG1{Mrz: m}

		if got := buildIdentityAttributes(doc).DateOfBirth; got != tc.wantDob {
			t.Errorf("DateOfBirth = %q, want %q", got, tc.wantDob)
		}
	}
}
