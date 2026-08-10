package document

import (
	"fmt"
	"time"

	"github.com/gmrtd/gmrtd/iso3166"
	"github.com/gmrtd/gmrtd/mrz"
	"github.com/gmrtd/gmrtd/utils"
)

// CountryInfo resolves an MRZ alpha-3 country code to its alpha-2 code and full name.
type CountryInfo struct {
	Alpha3 string `json:"alpha3,omitempty"`
	Alpha2 string `json:"alpha2,omitempty"`
	Name   string `json:"name,omitempty"`
}

// ResolveCountry resolves an MRZ alpha-3 country code (as found in DG1's IssuingState /
// Nationality) to a CountryInfo. Handles ICAO 9303 quirks such as Germany's special code
// "D" (mapped to "DEU").
func ResolveCountry(mrzAlpha3 string) (*CountryInfo, error) {
	// special handling for Germany per ICAO9303p3 (5. CODES FOR NATIONALITY...)
	if mrzAlpha3 == "D" {
		mrzAlpha3 = "DEU"
	}

	country := iso3166.ByAlpha3(mrzAlpha3)
	if country == nil {
		return nil, fmt.Errorf("[ResolveCountry] unable to resolve alpha-3 country code (%s)", mrzAlpha3)
	}

	return &CountryInfo{Alpha3: country.Alpha3, Alpha2: country.Alpha2, Name: country.Name}, nil
}

// resolveCountryTolerant resolves an MRZ alpha-3 country code to a CountryInfo, same as
// ResolveCountry. Unlike ResolveCountry, it never fails: MRZ country codes are sometimes
// fictitious (e.g. "UTO" for the fictitious country of Utopia, used by ICAO 9303
// sample/test documents) and can't be resolved to an alpha-2 code or name, so in that case
// it returns a CountryInfo with just the raw Alpha3 code set.
func resolveCountryTolerant(mrzAlpha3 string) *CountryInfo {
	if info, err := ResolveCountry(mrzAlpha3); err == nil {
		return info
	}

	return &CountryInfo{Alpha3: mrzAlpha3}
}

// ImageData is a raw image (e.g. face photo, signature) together with its detected format.
type ImageData struct {
	Data   []byte            `json:"data,omitempty"`
	Format utils.ImageFormat `json:"format,omitempty"`
}

func newImageData(raw []byte) ImageData {
	format, _ := utils.DetectImageFormat(raw)
	return ImageData{Data: raw, Format: format}
}

// IdentityAttributes is a flattened, client-friendly view of the data spread across a
// Document's Data Groups (DG1 MRZ, DG2, DG7, DG11, DG12, DG16). Where multiple DGs carry
// the same field, the higher-fidelity source wins - see buildIdentityAttributes for the
// precedence rules. It reflects whatever DG data is present regardless of whether that
// data has been cryptographically verified - see DocumentSummary.DataTrusted.
type IdentityAttributes struct {
	DocumentCode   string       `json:"documentCode,omitempty"`
	IssuingState   *CountryInfo `json:"issuingState,omitempty"`
	DocumentNumber string       `json:"documentNumber,omitempty"`
	Nationality    *CountryInfo `json:"nationality,omitempty"`
	Sex            string       `json:"sex,omitempty"`

	// Name is resolved from DG11 if present, else DG1 MRZ. NameMrzRaw is always the DG1
	// MRZ value (regardless of which source Name resolved to) since the MRZ name is
	// truncated/transliterated and clients may want to see/reconcile it against the
	// higher-fidelity DG11 name rather than rely on the precedence gmrtd applies.
	Name       *mrz.MrzName  `json:"name,omitempty"`
	NameMrzRaw *mrz.MrzName  `json:"nameMrzRaw,omitempty"`
	OtherNames []mrz.MrzName `json:"otherNames,omitempty"`

	// DateOfBirth is DG11's FullDateOfBirth (YYYYMMDD) if present, else the raw DG1 MRZ
	// value (YYMMDD, no century - MRZ carries no century for DOB and gmrtd does not guess
	// one). The raw, per-source values are also surfaced below since DOB may be present in
	// both DG1 and DG11, and clients may want to see/reconcile both rather than rely on the
	// precedence gmrtd applies.
	DateOfBirth        string `json:"dateOfBirth,omitempty"`
	DateOfBirthMrzRaw  string `json:"dateOfBirthMrzRaw,omitempty"`  // DG1 MRZ, raw YYMMDD (2-digit year)
	DateOfBirthDg11Raw string `json:"dateOfBirthDg11Raw,omitempty"` // DG11, raw YYYYMMDD

	// Age is the document holder's current age in whole years, set only when DateOfBirth
	// has an explicit century (DG11's 8-digit FullDateOfBirth). See PossibleAges for the
	// ambiguous DG1-MRZ-only case (6-digit YYMMDD, no century) - see resolveAge.
	Age *int `json:"age,omitempty"`

	// PossibleAges holds the candidate ages when DateOfBirth's century is ambiguous
	// (DG1-MRZ-only, 6-digit YYMMDD). Both the 19YY and 20YY interpretations of the 2-digit
	// year are tried, keeping whichever yield a plausible age (see resolveAge) - typically
	// both survive, since a 2-digit year is usually consistent with two centuries apart.
	// Ordered youngest to oldest (e.g. [12, 112]). Empty whenever Age is set, or
	// DateOfBirth is missing/unparseable.
	//
	// A single surviving entry is still a guess, not a confirmation: it means one century
	// was implausible, not that the other is certain. Don't treat len(PossibleAges) == 1
	// as equivalent to Age being set.
	PossibleAges []int `json:"possibleAges,omitempty"`

	// DateOfExpiry is DG1 MRZ's only source of expiry date, with its 2-digit year expanded
	// to an explicit century (YYYYMMDD) - see resolveExpiryDate for why that's safe to do
	// here, unlike DateOfBirth. DateOfExpiryMrzRaw is the untouched MRZ value.
	DateOfExpiry       string `json:"dateOfExpiry,omitempty"`
	DateOfExpiryMrzRaw string `json:"dateOfExpiryMrzRaw,omitempty"` // DG1 MRZ, raw YYMMDD (2-digit year)

	PlaceOfBirth []string `json:"placeOfBirth,omitempty"`
	Address      []string `json:"address,omitempty"`
	Telephone    string   `json:"telephone,omitempty"`
	Profession   string   `json:"profession,omitempty"`
	Title        string   `json:"title,omitempty"`

	PersonalNumber   string `json:"personalNumber,omitempty"`   // DG11 only
	MrzOptionalData  string `json:"mrzOptionalData,omitempty"`  // raw MRZ, unresolved
	MrzOptionalData2 string `json:"mrzOptionalData2,omitempty"` // TD1 only

	IssuingAuthority string `json:"issuingAuthority,omitempty"`

	// DateOfIssue is the raw DG12 value (YYYYMMDD), its only source.
	DateOfIssue    string `json:"dateOfIssue,omitempty"`
	DateOfIssueRaw string `json:"dateOfIssueRaw,omitempty"` // DG12, raw YYYYMMDD

	FaceImages         []ImageData `json:"faceImages,omitempty"`
	SignatureImages    []ImageData `json:"signatureImages,omitempty"`
	DocumentImageFront *ImageData  `json:"documentImageFront,omitempty"`
	DocumentImageRear  *ImageData  `json:"documentImageRear,omitempty"`

	PersonsToNotify []PersonToNotify `json:"personsToNotify,omitempty"`
}

// DocumentSummary is a client-friendly view of a document's overall trust/authenticity
// state, derived from a DocumentEx's Document + Session data. See DocumentEx.Summary,
// which computes it fresh on each call rather than storing it as session state.
type DocumentSummary struct {
	DataTrusted      bool           `json:"dataTrusted"`
	ChipAuthenticity ChipAuthStatus `json:"chipAuthenticity"`
	LdsVersion       string         `json:"ldsVersion,omitempty"`
	UnicodeVersion   string         `json:"unicodeVersion,omitempty"`

	// IdentityAttributes reflects whatever DG data is present, regardless of DataTrusted -
	// e.g. a failed Passive Authentication still surfaces the (unverified) MRZ/DG11/DG12
	// data, since callers may want to inspect it for manual review. DataTrusted is the sole
	// signal for whether this data has been cryptographically verified; callers must check
	// it before treating IdentityAttributes as authentic.
	IdentityAttributes *IdentityAttributes `json:"identityAttributes,omitempty"`
}

// resolveExpiryDate expands DG1 MRZ's 2-digit-year DateOfExpiry (YYMMDD) to an explicit
// 4-digit year (20YYMMDD). Unlike DateOfBirth, this is safe to assume without a pivot
// heuristic: DG1 (and therefore any expiry date) only exists on chip-enabled ePassports,
// which weren't issued before 2004, and realistic document validity periods (well under a
// century) mean a "19xx" reading isn't just unlikely, it's physically impossible given that
// history. This assumption holds only up to the year 2100 - revisit if gmrtd is still
// around by then. Falls back to the raw MRZ value if the constructed date doesn't parse
// (e.g. some issuers use sentinel values like "999999" for non-expiring documents, which
// ICAO 9303 doesn't officially support).
func resolveExpiryDate(mrzRaw string) string {
	fullYear := "20" + mrzRaw

	if _, err := time.Parse("20060102", fullYear); err != nil {
		return mrzRaw
	}

	return fullYear
}

// maxPlausibleAge bounds age inference from a DOB with an ambiguous century (see
// resolveAge). It's an oldest-known-living-person-plus-margin threshold, not a biological
// limit - used only to discard century interpretations that can't be right (e.g. a "19xx"
// reading that would make the holder centuries old is impossible; the "20xx" reading is
// then the only plausible one).
const maxPlausibleAge = 120

// resolveAge computes the document holder's current age from dob, which is either an
// unambiguous 8-digit YYYYMMDD (DG11's FullDateOfBirth) or an ambiguous 6-digit YYMMDD
// with no century (DG1 MRZ only). For the unambiguous case it returns a single age. For
// the ambiguous case it tries both the 20YY and 19YY interpretations of the 2-digit year
// and returns whichever produce a plausible age (not in the future, at most
// maxPlausibleAge) as possibleAges, youngest first - in practice this is usually both,
// since a 2-digit year is typically consistent with two birth years a century apart.
func resolveAge(dob string) (age *int, possibleAges []int) {
	now := time.Now()

	switch len(dob) {
	case 8:
		if birthDate, err := time.Parse("20060102", dob); err == nil {
			a := calculateAge(birthDate, now)
			age = &a
		}
	case 6:
		// Iterate 20YY before 19YY so possibleAges comes out youngest-first (e.g. [12, 112]).
		for _, century := range [...]string{"20", "19"} {
			birthDate, err := time.Parse("20060102", century+dob)
			if err != nil || birthDate.After(now) {
				continue
			}
			if a := calculateAge(birthDate, now); a <= maxPlausibleAge {
				possibleAges = append(possibleAges, a)
			}
		}
	}

	return age, possibleAges
}

// calculateAge returns the number of whole years elapsed between birthDate and now.
func calculateAge(birthDate, now time.Time) int {
	age := now.Year() - birthDate.Year()
	if now.Month() < birthDate.Month() || (now.Month() == birthDate.Month() && now.Day() < birthDate.Day()) {
		age--
	}
	return age
}

// buildIdentityAttributes resolves an IdentityAttributes from doc's Data Groups. Every DG
// is optional per LDS1, so every access is nil-safe. Field precedence where more than one
// DG carries the same data:
//   - Name/DateOfBirth: DG11 wins over DG1 MRZ when present - DG11 has full-fidelity
//     names (MRZ truncates/transliterates) and an explicit-century date of birth. The DG1
//     MRZ value is still surfaced separately (NameMrzRaw/DateOfBirthMrzRaw) even when
//     overridden.
//   - PersonalNumber: DG11 only. MRZ's optional-data fields are issuer-discretionary and
//     not reliably a personal number, so they're surfaced separately, unresolved.
func buildIdentityAttributes(doc *Document) *IdentityAttributes {
	summary := &IdentityAttributes{}

	dg1 := doc.Mf.Lds1.Dg1
	dg2 := doc.Mf.Lds1.Dg2
	dg7 := doc.Mf.Lds1.Dg7
	dg11 := doc.Mf.Lds1.Dg11
	dg12 := doc.Mf.Lds1.Dg12
	dg16 := doc.Mf.Lds1.Dg16

	if dg1 != nil && dg1.Mrz != nil {
		m := dg1.Mrz

		summary.DocumentCode = m.DocumentCode
		summary.DocumentNumber = m.DocumentNumber
		summary.Sex = m.Sex
		summary.Name = m.NameOfHolder
		summary.NameMrzRaw = m.NameOfHolder
		summary.MrzOptionalData = m.OptionalData
		summary.MrzOptionalData2 = m.OptionalData2

		if len(m.IssuingState) > 0 {
			summary.IssuingState = resolveCountryTolerant(m.IssuingState)
		}
		if len(m.Nationality) > 0 {
			summary.Nationality = resolveCountryTolerant(m.Nationality)
		}

		if len(m.DateOfBirth) > 0 {
			summary.DateOfBirthMrzRaw = m.DateOfBirth
			// MRZ carries no century for DOB; surface the raw YYMMDD value as-is rather than
			// guess. DG11's FullDateOfBirth (explicit century), if present, overrides below.
			summary.DateOfBirth = m.DateOfBirth
		}
		if len(m.DateOfExpiry) > 0 {
			summary.DateOfExpiryMrzRaw = m.DateOfExpiry
			summary.DateOfExpiry = resolveExpiryDate(m.DateOfExpiry)
		}
	}

	if dg11 != nil {
		d := dg11.Details

		if d.NameOfHolder != nil {
			summary.Name = d.NameOfHolder
		}
		summary.OtherNames = d.OtherNames
		summary.PersonalNumber = d.PersonalNumber
		summary.PlaceOfBirth = d.PlaceOfBirth
		summary.Address = d.Address
		summary.Telephone = d.Telephone
		summary.Profession = d.Profession
		summary.Title = d.Title

		if len(d.FullDateOfBirth) > 0 {
			summary.DateOfBirthDg11Raw = d.FullDateOfBirth
			summary.DateOfBirth = d.FullDateOfBirth
		}
	}

	if len(summary.DateOfBirth) > 0 {
		summary.Age, summary.PossibleAges = resolveAge(summary.DateOfBirth)
	}

	if dg12 != nil {
		d := dg12.Details

		summary.IssuingAuthority = d.IssuingAuthority

		if len(d.DateOfIssue) > 0 {
			summary.DateOfIssueRaw = d.DateOfIssue
			summary.DateOfIssue = d.DateOfIssue
		}

		if len(d.ImageFront) > 0 {
			img := newImageData(d.ImageFront)
			summary.DocumentImageFront = &img
		}
		if len(d.ImageRear) > 0 {
			img := newImageData(d.ImageRear)
			summary.DocumentImageRear = &img
		}
	}

	if dg2 != nil {
		for _, image := range dg2.Images {
			summary.FaceImages = append(summary.FaceImages, newImageData(image.Image))
		}
	}

	if dg7 != nil {
		for _, image := range dg7.Images {
			summary.SignatureImages = append(summary.SignatureImages, newImageData(image.Image))
		}
	}

	if dg16 != nil {
		summary.PersonsToNotify = dg16.PersonsToNotify
	}

	return summary
}
