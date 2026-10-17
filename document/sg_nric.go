package document

import (
	"regexp"
	"strings"

	"github.com/gmrtd/gmrtd/mrz"
)

// Singapore passports carry only a 2-digit year of birth (DG1 MRZ) and, as of today, no DG11
// FullDateOfBirth. They do carry the holder's NRIC in the MRZ optional data, whose prefix
// encodes the century of birth for Singapore citizens and PRs: 'S' = born before 2000 (19xx),
// 'T' = born 2000 onwards (20xx). FIN prefixes (F/G/M, foreigners) don't encode it.
//
// NB the NRIC is sensitive personal data - never log it.

var sgNricPattern = regexp.MustCompile(`^[ST][0-9]{7}[A-Z]$`)

var sgNricWeights = [...]int{2, 7, 6, 5, 4, 3, 2}

// check letters for S/T NRICs, indexed by the weighted digit sum (+4 for T) modulo 11
const sgNricCheckLetters = "JZIHGFEDCBA"

// sgNricCentury returns the century of birth ("19" for an 'S' NRIC, "20" for a 'T' NRIC)
// encoded by a well-formed NRIC with a valid check letter, or "" otherwise.
func sgNricCentury(nric string) string {
	nric = strings.TrimSpace(nric)
	if !sgNricPattern.MatchString(nric) {
		return ""
	}

	sum := 0
	for i, w := range sgNricWeights {
		sum += int(nric[1+i]-'0') * w
	}
	if nric[0] == 'T' {
		sum += 4
	}
	if nric[8] != sgNricCheckLetters[sum%11] {
		return ""
	}

	if nric[0] == 'T' {
		return "20"
	}
	return "19"
}

// isSgPassport reports whether m is a Singapore passport held by a Singapore national - the
// only case where the MRZ optional data is the holder's S/T NRIC.
func isSgPassport(m *mrz.MRZ) bool {
	return m != nil &&
		strings.HasPrefix(m.DocumentCode, "P") &&
		m.IssuingState == "SGP" &&
		m.Nationality == "SGP"
}
