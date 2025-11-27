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
	}
	for _, tc := range testCases {
		country := ByAlpha2(tc.alpha2)

		if country != nil {
			t.Errorf("Error expected (alpha2:%s)", tc.alpha2)
		}
	}
}

func TesrByAlpha3(t *testing.T) {
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
	}
	for _, tc := range testCases {
		country := ByAlpha3(tc.alpha3)

		if country != nil {
			t.Errorf("Error expected (alpha3:%s)", tc.alpha3)
		}
	}
}
