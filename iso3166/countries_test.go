package iso3166

import "testing"

func TestByAlpha2(t *testing.T) {
	testCases := []struct {
		alpha2    string
		expAlpha3 string
	}{
		{
			alpha2:    "SG",
			expAlpha3: "SGP",
		},
		{
			alpha2:    "sg",
			expAlpha3: "SGP",
		},
	}
	for _, tc := range testCases {
		country := ByAlpha2(tc.alpha2)

		if country == nil {
			t.Errorf("Unable to locate country (alpha2:%s)", tc.alpha2)
		} else if country.Alpha3 != tc.expAlpha3 {
			t.Errorf("Country differs to expected - alpha3 (exp:%s, act:%s)", tc.expAlpha3, country.Alpha3)
		}
	}
}

func TestByAlpha2Errors(t *testing.T) {
	testCases := []struct {
		alpha2 string
	}{
		{
			// 'uk' is reserved, but not a valid country code
			alpha2: "UK",
		},
		{
			// fictional country (utopia) used for icao9303 test documents
			alpha2: "UT",
		},
		{
			alpha2: "",
		},
	}
	for _, tc := range testCases {
		country := ByAlpha2(tc.alpha2)

		if country != nil {
			t.Errorf("Error expected (alpha2:%s)", tc.alpha2)
		}
	}
}

func TestByAlpha3(t *testing.T) {
	testCases := []struct {
		alpha3    string
		expAlpha2 string
	}{
		{
			alpha3:    "GBR",
			expAlpha2: "GB",
		},
		{
			alpha3:    "gbr",
			expAlpha2: "GB",
		},
	}
	for _, tc := range testCases {
		country := ByAlpha3(tc.alpha3)

		if country == nil {
			t.Errorf("Unable to locate country (alpha3:%s)", tc.alpha3)
		} else if country.Alpha2 != tc.expAlpha2 {
			t.Errorf("Country differs to expected - alpha3 (exp:%s, act:%s)", tc.expAlpha2, country.Alpha2)
		}
	}
}

func TestByAlpha3Errors(t *testing.T) {
	testCases := []struct {
		alpha3 string
	}{
		{
			// non-existent country
			alpha3: "ART",
		},
		{
			// fictional country (utopia) used for icao9303 test documents
			alpha3: "UTO",
		},
		{
			// the European Union entry has no alpha-3, so "" must not match it
			alpha3: "",
		},
	}
	for _, tc := range testCases {
		country := ByAlpha3(tc.alpha3)

		if country != nil {
			t.Errorf("Error expected (alpha3:%s)", tc.alpha3)
		}
	}
}

// officially assigned ISO 3166-1 alpha-2 codes (249), per the ISO Online Browsing Platform
var assignedAlpha2Codes = []string{
	"AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
	"BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS",
	"BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
	"CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
	"EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
	"GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
	"HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM",
	"JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC",
	"LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
	"ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
	"NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG",
	"PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
	"SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS",
	"ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
	"TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
	"VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW",
}

func TestCountriesCoverAllAssignedCodes(t *testing.T) {
	for _, alpha2 := range assignedAlpha2Codes {
		country := ByAlpha2(alpha2)
		if country == nil {
			t.Errorf("Unable to locate country (alpha2:%s)", alpha2)
			continue
		}

		if byAlpha3 := ByAlpha3(country.Alpha3); byAlpha3 == nil || byAlpha3.Alpha2 != alpha2 {
			t.Errorf("Alpha3 lookup does not round-trip (alpha2:%s, alpha3:%s)", alpha2, country.Alpha3)
		}
	}
}

func TestCountriesHaveUniqueCodes(t *testing.T) {
	seenAlpha2 := make(map[string]bool, len(Countries))
	seenAlpha3 := make(map[string]bool, len(Countries))

	for _, country := range Countries {
		if seenAlpha2[country.Alpha2] {
			t.Errorf("Duplicate alpha2 (alpha2:%s)", country.Alpha2)
		}
		// the European Union entry deliberately has no alpha3
		if country.Alpha3 != "" && seenAlpha3[country.Alpha3] {
			t.Errorf("Duplicate alpha3 (alpha3:%s)", country.Alpha3)
		}

		seenAlpha2[country.Alpha2] = true
		seenAlpha3[country.Alpha3] = true
	}
}
