package document

import (
	"testing"

	"github.com/gmrtd/gmrtd/mrz"
	"github.com/gmrtd/gmrtd/utils"
)

var jpegTestBytes []byte = utils.HexToBytes("ffd8ffe000104a46494600010100000100010000ffdb004300ffdb004301010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101ffc0000b080001000101011100ffc40014000100000000000000000000000000000000ffc40014100100000000000000000000000000000000ffda0008010100003f00d2cf20ffd9")

func TestResolveCountry(t *testing.T) {
	info, err := ResolveCountry("FRA")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if info.Alpha2 != "FR" || info.Alpha3 != "FRA" || info.Name != "France" {
		t.Errorf("unexpected CountryInfo: %+v", info)
	}
}

func TestResolveCountryGermanySpecialCase(t *testing.T) {
	info, err := ResolveCountry("D")
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if info.Alpha2 != "DE" || info.Alpha3 != "DEU" || info.Name != "Germany" {
		t.Errorf("unexpected CountryInfo: %+v", info)
	}
}

func TestResolveCountryUnresolvable(t *testing.T) {
	if _, err := ResolveCountry("UTO"); err == nil {
		t.Error("expected error for unresolvable (fictitious) country code")
	}
}

func TestResolveCountryTolerantFallsBackToRawAlpha3(t *testing.T) {
	info := resolveCountryTolerant("UTO")
	if info == nil || info.Alpha3 != "UTO" || info.Alpha2 != "" || info.Name != "" {
		t.Errorf("resolveCountryTolerant(UTO) = %+v, want {Alpha3:UTO}", info)
	}
}

func TestResolveCountryTolerantResolvesKnownCode(t *testing.T) {
	info := resolveCountryTolerant("FRA")
	if info == nil || info.Alpha2 != "FR" || info.Alpha3 != "FRA" || info.Name != "France" {
		t.Errorf("resolveCountryTolerant(FRA) = %+v", info)
	}
}

func TestBuildIdentityAttributesNilDocument(t *testing.T) {
	summary := buildIdentityAttributes(&Document{})

	if summary == nil {
		t.Fatal("expected non-nil IdentityAttributes even when no DGs are present")
	}
	if summary.Name != nil || summary.DateOfBirth != "" || len(summary.FaceImages) != 0 {
		t.Errorf("expected an empty summary, got %+v", summary)
	}
}

func TestBuildIdentityAttributesSampleDocument(t *testing.T) {
	doc, err := SampleDocument()
	if err != nil {
		t.Fatalf("SampleDocument error: %s", err)
	}

	summary := buildIdentityAttributes(doc)

	if summary.DocumentCode != "I" {
		t.Errorf("DocumentCode = %q, want %q", summary.DocumentCode, "I")
	}
	if summary.DocumentNumber != "D23145890" {
		t.Errorf("DocumentNumber = %q, want %q", summary.DocumentNumber, "D23145890")
	}
	if summary.Sex != "F" {
		t.Errorf("Sex = %q, want %q", summary.Sex, "F")
	}

	// DG11's NameOfHolder wins over DG1 MRZ's, but the raw MRZ name is still surfaced
	if summary.Name == nil || summary.Name.Primary != "SMITH" || summary.Name.Secondary != "JOHN J" {
		t.Errorf("Name = %+v, want SMITH/JOHN J (DG11 should win over DG1 MRZ)", summary.Name)
	}
	if summary.NameMrzRaw == nil || summary.NameMrzRaw.Primary != "ERIKSSON" || summary.NameMrzRaw.Secondary != "ANNA MARIA" {
		t.Errorf("NameMrzRaw = %+v, want ERIKSSON/ANNA MARIA (DG1 MRZ value)", summary.NameMrzRaw)
	}

	// DG11 sample has no FullDateOfBirth tag, so DOB falls back to the raw DG1 MRZ value
	// (740812) - no century is guessed
	if summary.DateOfBirth != "740812" {
		t.Errorf("DateOfBirth = %q, want %q", summary.DateOfBirth, "740812")
	}
	if summary.DateOfBirthMrzRaw != "740812" {
		t.Errorf("DateOfBirthMrzRaw = %q, want %q", summary.DateOfBirthMrzRaw, "740812")
	}
	if summary.DateOfBirthDg11Raw != "" {
		t.Errorf("DateOfBirthDg11Raw = %q, want empty (sample has no FullDateOfBirth tag)", summary.DateOfBirthDg11Raw)
	}

	// DG1 MRZ is DateOfExpiry's only source, so both fields hold the same raw value
	// (120415) - no century is guessed
	if summary.DateOfExpiry != "120415" {
		t.Errorf("DateOfExpiry = %q, want %q", summary.DateOfExpiry, "120415")
	}
	if summary.DateOfExpiryMrzRaw != "120415" {
		t.Errorf("DateOfExpiryMrzRaw = %q, want %q", summary.DateOfExpiryMrzRaw, "120415")
	}

	// DG1's fictitious "UTO" issuing-state/nationality cannot be resolved to an
	// alpha-2/name, but the raw alpha-3 code is still surfaced
	if summary.IssuingState == nil || summary.IssuingState.Alpha3 != "UTO" || summary.IssuingState.Alpha2 != "" || summary.IssuingState.Name != "" {
		t.Errorf("IssuingState = %+v, want {Alpha3:UTO} (fictitious 'UTO' code)", summary.IssuingState)
	}
	if summary.Nationality == nil || summary.Nationality.Alpha3 != "UTO" || summary.Nationality.Alpha2 != "" || summary.Nationality.Name != "" {
		t.Errorf("Nationality = %+v, want {Alpha3:UTO} (fictitious 'UTO' code)", summary.Nationality)
	}

	if len(summary.PlaceOfBirth) != 2 || summary.PlaceOfBirth[0] != "ANYTOWN" {
		t.Errorf("PlaceOfBirth = %v", summary.PlaceOfBirth)
	}
	if summary.Telephone != "16125551212" {
		t.Errorf("Telephone = %q", summary.Telephone)
	}
	if summary.Profession != "TRAVEL AGENT" {
		t.Errorf("Profession = %q", summary.Profession)
	}

	if len(summary.FaceImages) != 1 || summary.FaceImages[0].Format != utils.ImageFormatJPEG {
		t.Errorf("FaceImages = %+v", summary.FaceImages)
	}
	if len(summary.SignatureImages) != 1 || summary.SignatureImages[0].Format != utils.ImageFormatJPEG {
		t.Errorf("SignatureImages = %+v", summary.SignatureImages)
	}

	if len(summary.PersonsToNotify) != 2 {
		t.Fatalf("PersonsToNotify = %d entries, want 2", len(summary.PersonsToNotify))
	}
	if summary.PersonsToNotify[0].Name == nil || summary.PersonsToNotify[0].Name.Primary != "SMITH" {
		t.Errorf("PersonsToNotify[0] = %+v", summary.PersonsToNotify[0])
	}
}

func TestBuildIdentityAttributesDobPrecedenceDg11WinsOverMrz(t *testing.T) {
	doc := &Document{}
	doc.Mf.Lds1.Dg1 = &DG1{Mrz: &mrz.MRZ{DateOfBirth: "740812"}}
	doc.Mf.Lds1.Dg11 = &DG11{Details: PersonDetails{FullDateOfBirth: "20210915"}}

	summary := buildIdentityAttributes(doc)

	// resolved DOB favours DG11, but both raw sources remain independently visible
	if summary.DateOfBirth != "20210915" {
		t.Errorf("DateOfBirth = %q, want %q (DG11 FullDateOfBirth should win over MRZ)", summary.DateOfBirth, "20210915")
	}
	if summary.DateOfBirthMrzRaw != "740812" {
		t.Errorf("DateOfBirthMrzRaw = %q, want %q", summary.DateOfBirthMrzRaw, "740812")
	}
	if summary.DateOfBirthDg11Raw != "20210915" {
		t.Errorf("DateOfBirthDg11Raw = %q, want %q", summary.DateOfBirthDg11Raw, "20210915")
	}
}

func TestBuildIdentityAttributesNamePrecedenceDg11WinsOverMrz(t *testing.T) {
	doc := &Document{}
	doc.Mf.Lds1.Dg1 = &DG1{Mrz: &mrz.MRZ{NameOfHolder: &mrz.MrzName{Primary: "ERIKSSON", Secondary: "ANNA MARIA"}}}
	doc.Mf.Lds1.Dg11 = &DG11{Details: PersonDetails{NameOfHolder: &mrz.MrzName{Primary: "SMITH", Secondary: "JOHN J"}}}

	summary := buildIdentityAttributes(doc)

	// resolved Name favours DG11, but the raw MRZ name remains independently visible
	if summary.Name == nil || summary.Name.Primary != "SMITH" || summary.Name.Secondary != "JOHN J" {
		t.Errorf("Name = %+v, want SMITH/JOHN J (DG11 should win over DG1 MRZ)", summary.Name)
	}
	if summary.NameMrzRaw == nil || summary.NameMrzRaw.Primary != "ERIKSSON" || summary.NameMrzRaw.Secondary != "ANNA MARIA" {
		t.Errorf("NameMrzRaw = %+v, want ERIKSSON/ANNA MARIA (DG1 MRZ value)", summary.NameMrzRaw)
	}
}

func TestBuildIdentityAttributesMrzOnlyDobNoCenturyGuessed(t *testing.T) {
	doc := &Document{}
	doc.Mf.Lds1.Dg1 = &DG1{Mrz: &mrz.MRZ{DateOfBirth: "050615"}}

	summary := buildIdentityAttributes(doc)

	// no DG11, so DateOfBirth is the raw MRZ value as-is - gmrtd does not guess a century
	if summary.DateOfBirth != "050615" {
		t.Errorf("DateOfBirth = %q, want %q", summary.DateOfBirth, "050615")
	}
}

// PersonalNumber (DG11 only) and MRZ optional data must be kept separate - MRZ optional
// data is issuer-discretionary and should not be assumed to be a personal number.
func TestBuildIdentityAttributesPersonalNumberNotConflatedWithMrzOptionalData(t *testing.T) {
	doc := &Document{}
	doc.Mf.Lds1.Dg1 = &DG1{Mrz: &mrz.MRZ{OptionalData: "SOMEDATA", OptionalData2: "MOREDATA"}}
	doc.Mf.Lds1.Dg11 = &DG11{Details: PersonDetails{PersonalNumber: "12345678"}}

	summary := buildIdentityAttributes(doc)

	if summary.PersonalNumber != "12345678" {
		t.Errorf("PersonalNumber = %q, want %q", summary.PersonalNumber, "12345678")
	}
	if summary.MrzOptionalData != "SOMEDATA" {
		t.Errorf("MrzOptionalData = %q, want %q", summary.MrzOptionalData, "SOMEDATA")
	}
	if summary.MrzOptionalData2 != "MOREDATA" {
		t.Errorf("MrzOptionalData2 = %q, want %q", summary.MrzOptionalData2, "MOREDATA")
	}
}

func TestBuildIdentityAttributesDg12IssuingAuthorityDateOfIssueAndImages(t *testing.T) {
	doc := &Document{}
	doc.Mf.Lds1.Dg12 = &DG12{Details: DocumentDetails{
		IssuingAuthority: "JAKARTA - AMBASSADE DE FRANCE EN INDONESIE",
		DateOfIssue:      "20170905",
		ImageFront:       jpegTestBytes,
		ImageRear:        jpegTestBytes,
	}}

	summary := buildIdentityAttributes(doc)

	if summary.IssuingAuthority != "JAKARTA - AMBASSADE DE FRANCE EN INDONESIE" {
		t.Errorf("IssuingAuthority = %q", summary.IssuingAuthority)
	}

	if summary.DateOfIssue != "20170905" {
		t.Errorf("DateOfIssue = %q, want %q", summary.DateOfIssue, "20170905")
	}
	if summary.DateOfIssueRaw != "20170905" {
		t.Errorf("DateOfIssueRaw = %q, want %q", summary.DateOfIssueRaw, "20170905")
	}

	if summary.DocumentImageFront == nil || summary.DocumentImageFront.Format != utils.ImageFormatJPEG {
		t.Errorf("DocumentImageFront = %+v", summary.DocumentImageFront)
	}
	if summary.DocumentImageRear == nil || summary.DocumentImageRear.Format != utils.ImageFormatJPEG {
		t.Errorf("DocumentImageRear = %+v", summary.DocumentImageRear)
	}
}

func TestBuildIdentityAttributesCountryResolution(t *testing.T) {
	doc := &Document{}
	doc.Mf.Lds1.Dg1 = &DG1{Mrz: &mrz.MRZ{IssuingState: "DEU", Nationality: "FRA"}}

	summary := buildIdentityAttributes(doc)

	if summary.IssuingState == nil || summary.IssuingState.Alpha2 != "DE" || summary.IssuingState.Name != "Germany" {
		t.Errorf("IssuingState = %+v", summary.IssuingState)
	}
	if summary.Nationality == nil || summary.Nationality.Alpha2 != "FR" || summary.Nationality.Name != "France" {
		t.Errorf("Nationality = %+v", summary.Nationality)
	}
}

func TestSummaryIdentityAttributesPopulatedWhenTrusted(t *testing.T) {
	docEx := &DocumentEx{
		Session: Session{
			PassiveAuthResult: &PassiveAuthResult{Success: true, Sod: NewPassiveAuth(nil)},
		},
	}
	docEx.Document.Mf.Lds1.Dg1 = &DG1{Mrz: &mrz.MRZ{DocumentNumber: "D23145890"}}

	summary := docEx.Summary()

	if !summary.DataTrusted {
		t.Fatal("expected DataTrusted to be true")
	}
	if summary.IdentityAttributes == nil {
		t.Fatal("expected IdentityAttributes to be populated when DataTrusted is true")
	}
	if summary.IdentityAttributes.DocumentNumber != "D23145890" {
		t.Errorf("IdentityAttributes.DocumentNumber = %q", summary.IdentityAttributes.DocumentNumber)
	}
}

// IdentityAttributes still reflects the (unverified) DG data even when DataTrusted is
// false - callers may want to inspect it for manual review, but must check DataTrusted
// before treating it as authentic.
func TestSummaryIdentityAttributesStillPopulatedWhenNotTrusted(t *testing.T) {
	docEx := &DocumentEx{
		Session: Session{
			PassiveAuthResult: &PassiveAuthResult{Success: false},
		},
	}
	docEx.Document.Mf.Lds1.Dg1 = &DG1{Mrz: &mrz.MRZ{DocumentNumber: "D23145890"}}

	summary := docEx.Summary()

	if summary.DataTrusted {
		t.Fatal("expected DataTrusted to be false")
	}
	if summary.IdentityAttributes == nil {
		t.Fatal("expected IdentityAttributes to still be populated even when DataTrusted is false")
	}
	if summary.IdentityAttributes.DocumentNumber != "D23145890" {
		t.Errorf("IdentityAttributes.DocumentNumber = %q", summary.IdentityAttributes.DocumentNumber)
	}
}
