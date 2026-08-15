package main

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/cryptoutils"
	"github.com/gmrtd/gmrtd/internal/version"
	"github.com/gmrtd/gmrtd/iso3166"
	"github.com/gmrtd/gmrtd/utils"
)

type CertRecord struct {
	Cert    *cms.Certificate
	Sources map[string]struct{}
}

func NewCertRecord() *CertRecord {
	return &CertRecord{Sources: make(map[string]struct{})}
}

type CountryCerts struct {
	ByFingerprint map[string]*CertRecord
}

func NewCountryCerts() *CountryCerts {
	return &CountryCerts{ByFingerprint: make(map[string]*CertRecord)}
}

func (cc *CountryCerts) GetOrCreate(cert cms.Certificate) *CertRecord {
	certFingerprint := utils.BytesToHex(cryptoutils.CryptoHash(crypto.SHA256, cert.Raw))

	if existing, exists := cc.ByFingerprint[certFingerprint]; exists {
		return existing
	}

	cr := NewCertRecord()
	cr.Cert = &cert
	cc.ByFingerprint[certFingerprint] = cr

	return cr
}

func cscaSkiSet(certs map[string]*CertRecord) map[string]struct{} {
	skis := make(map[string]struct{})
	for _, cr := range certs {
		if isLinkCert(cr.Cert) {
			continue
		}
		ski, _ := cr.Cert.TbsCertificate.Extensions.SubjectKeyIdentifier()
		if ski == nil {
			continue
		}
		skis[utils.BytesToHex([]byte(*ski))] = struct{}{}
	}
	return skis
}

func filterBrokenLinkCerts(certs map[string]*CertRecord, cscaSkis map[string]struct{}) []*CertRecord {
	var broken []*CertRecord
	for _, cr := range certs {
		if !isLinkCert(cr.Cert) {
			continue
		}
		aki, _ := cr.Cert.TbsCertificate.Extensions.AuthorityKeyIdentifier()
		if aki == nil {
			continue
		}
		if _, found := cscaSkis[utils.BytesToHex(aki.KeyIdentifier)]; found {
			continue
		}
		broken = append(broken, cr)
	}
	return broken
}

// BrokenLinkCerts returns link certs whose AKI does not match any CSCA SKI in this country.
func (cc *CountryCerts) BrokenLinkCerts() []*CertRecord {
	return filterBrokenLinkCerts(cc.ByFingerprint, cscaSkiSet(cc.ByFingerprint))
}

type AllCerts struct {
	ByCountry map[string]*CountryCerts
}

func NewAllCerts() *AllCerts {
	return &AllCerts{ByCountry: make(map[string]*CountryCerts)}
}

func (ac *AllCerts) GetOrCreate(countryAlpha2 string) *CountryCerts {
	countryAlpha2 = strings.ToUpper(countryAlpha2)

	if existing, exists := ac.ByCountry[countryAlpha2]; exists {
		return existing
	}

	cc := NewCountryCerts()
	ac.ByCountry[countryAlpha2] = cc

	return cc
}

var (
	germanMasterListFn          = cms.GermanMasterList
	dutchMasterListFn           = cms.DutchMasterList
	indonesian2010SeriesCertsFn = cms.Indonesian2010SeriesCerts
)

type namedPool struct {
	name string
	pool cms.CertPool
}

func isLinkCert(cert *cms.Certificate) bool {
	ski, _ := cert.TbsCertificate.Extensions.SubjectKeyIdentifier()
	aki, _ := cert.TbsCertificate.Extensions.AuthorityKeyIdentifier()

	if ski == nil || aki == nil || bytes.Equal(*ski, aki.KeyIdentifier) {
		return false
	}

	return true
}

func formatValidity(validity cms.Validity) string {
	notBefore, notAfter, err := validity.Parse()
	if err != nil {
		return "?..?"
	}

	return fmt.Sprintf("%s..%s", notBefore.Format("2006-01-02"), notAfter.Format("2006-01-02"))
}

func formatKeyType(cert *cms.Certificate) string {
	spki, err := cms.Asn1decodeSubjectPublicKeyInfo(cert.TbsCertificate.SubjectPublicKeyInfo.FullBytes)
	if err != nil {
		return "?"
	}

	if spki.IsEC() {
		curve, err := spki.EcCurve()
		if err != nil {
			return "EC(?)"
		}
		return fmt.Sprintf("EC(%s)", cms.GetCurveName(*curve))
	}

	if spki.IsRSA() {
		rsaKey, err := spki.RsaPubKey()
		if err != nil {
			return "RSA(?)"
		}
		return fmt.Sprintf("RSA(%d)", rsaKey.N.BitLen())
	}

	return "?"
}

func formatSources(sources map[string]struct{}) string {
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	return "[" + strings.Join(names, ",") + "]"
}

func sortedFingerprints(m map[string]*CertRecord) []string {
	fps := make([]string, 0, len(m))
	for fp := range m {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	return fps
}

func skiHex(cert *cms.Certificate) string {
	ski, _ := cert.TbsCertificate.Extensions.SubjectKeyIdentifier()
	if ski == nil {
		return "?"
	}
	return fmt.Sprintf("%X", []byte(*ski))
}

func subjectDN(cert *cms.Certificate) string {
	rdn, err := cert.TbsCertificate.SubjectRDN()
	if err != nil || rdn == nil {
		return "?"
	}
	s := rdn.String()
	if s == "" {
		return "?"
	}
	return s
}

func buildAllCerts(pools []namedPool, countries []iso3166.Country) *AllCerts {
	ac := NewAllCerts()

	for _, np := range pools {
		for _, country := range countries {
			cc := ac.GetOrCreate(country.Alpha2)
			for _, cert := range np.pool.ByIssuerCountry(country.Alpha2) {
				cr := cc.GetOrCreate(cert)
				cr.Sources[np.name] = struct{}{}
			}
		}
	}

	return ac
}

func akiHexOf(cert *cms.Certificate) string {
	aki, _ := cert.TbsCertificate.Extensions.AuthorityKeyIdentifier()
	if aki == nil {
		return "?"
	}
	return fmt.Sprintf("%X", aki.KeyIdentifier)
}

func toCertRecordSet(records []*CertRecord) map[*CertRecord]struct{} {
	set := make(map[*CertRecord]struct{}, len(records))
	for _, cr := range records {
		set[cr] = struct{}{}
	}
	return set
}

func sortBySki(records []*CertRecord) {
	sort.Slice(records, func(i, j int) bool { return skiHex(records[i].Cert) < skiHex(records[j].Cert) })
}

// printCscaTable prints the CSCA table for a country and returns the CSCA cert count.
func printCscaTable(w io.Writer, cc *CountryCerts) int {
	var cscaCnt int

	fmt.Fprintf(w, "  CSCA:\n")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "    SKI\tVALID\tKEY\tSOURCES\tSUBJECT")
	for _, fp := range sortedFingerprints(cc.ByFingerprint) {
		cr := cc.ByFingerprint[fp]
		if isLinkCert(cr.Cert) {
			continue
		}
		cscaCnt++
		fmt.Fprintf(tw, "    %s\t%s\t%s\t%s\t%s\n",
			skiHex(cr.Cert),
			formatValidity(cr.Cert.TbsCertificate.Validity),
			formatKeyType(cr.Cert),
			formatSources(cr.Sources),
			subjectDN(cr.Cert),
		)
	}
	tw.Flush()
	fmt.Fprintf(w, "\n")

	return cscaCnt
}

// printLinkTable prints the LINK table for a country (excluding broken links) and returns the link cert count.
func printLinkTable(w io.Writer, cc *CountryCerts, brokenSet map[*CertRecord]struct{}) int {
	var linkCnt int

	fmt.Fprintf(w, "  LINK:\n")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "    AKI\t\tSKI\tVALID\tKEY\tSOURCES")
	for _, fp := range sortedFingerprints(cc.ByFingerprint) {
		cr := cc.ByFingerprint[fp]
		if !isLinkCert(cr.Cert) {
			continue
		}
		linkCnt++
		if _, isBroken := brokenSet[cr]; isBroken {
			continue
		}
		fmt.Fprintf(tw, "    %s\t->\t%s\t%s\t%s\t%s\n",
			akiHexOf(cr.Cert),
			skiHex(cr.Cert),
			formatValidity(cr.Cert.TbsCertificate.Validity),
			formatKeyType(cr.Cert),
			formatSources(cr.Sources),
		)
	}
	tw.Flush()

	return linkCnt
}

func printBrokenLinksTable(w io.Writer, broken []*CertRecord) {
	if len(broken) == 0 {
		return
	}

	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  BROKEN LINKS:\n")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "    AKI\tSKI\tNOTE")
	for _, cr := range broken {
		fmt.Fprintf(tw, "    %s\t%s\t%s\n", akiHexOf(cr.Cert), skiHex(cr.Cert), "parent CSCA not in master list")
	}
	tw.Flush()
}

type countryStats struct {
	cscaCnt   int
	linkCnt   int
	brokenCnt int
}

// printCountryReport prints the full report block for a country (CSCA/LINK/BROKEN LINKS
// tables) and returns its cert counts. It prints nothing and returns a zero countryStats
// if the country has no certs.
func printCountryReport(w io.Writer, country iso3166.Country, cc *CountryCerts) countryStats {
	if len(cc.ByFingerprint) < 1 {
		return countryStats{}
	}

	fmt.Fprintf(w, "[%-2s] %s [cnt:%1d]\n\n", country.Alpha2, country.Name, len(cc.ByFingerprint))

	cscaCnt := printCscaTable(w, cc)

	broken := cc.BrokenLinkCerts()
	sortBySki(broken)
	brokenSet := toCertRecordSet(broken)

	linkCnt := printLinkTable(w, cc, brokenSet)
	printBrokenLinksTable(w, broken)

	fmt.Fprintf(w, "\n")

	return countryStats{cscaCnt: cscaCnt, linkCnt: linkCnt, brokenCnt: len(broken)}
}

func printSummary(w io.Writer, total countryStats, countriesWithCscaCnt, countriesWithLinkCnt int) {
	fmt.Fprintf(w, "\n\n\n")
	fmt.Fprintf(w, "CSCA certificate count (unique): %d\n", total.cscaCnt)
	fmt.Fprintf(w, "Link certificate count (unique): %d\n", total.linkCnt)
	fmt.Fprintf(w, "Broken link count:               %d\n", total.brokenCnt)
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "Countries with CSCA certificates: %d\n", countriesWithCscaCnt)
	fmt.Fprintf(w, "Countries with Link certificates: %d\n", countriesWithLinkCnt)
	fmt.Fprintf(w, "\n")
}

func run(pools []namedPool, countries []iso3166.Country, w io.Writer) {
	ac := buildAllCerts(pools, countries)

	var total countryStats
	var countriesWithCscaCnt int
	var countriesWithLinkCnt int

	for _, country := range countries {
		cc := ac.GetOrCreate(country.Alpha2)
		stats := printCountryReport(w, country, cc)

		total.cscaCnt += stats.cscaCnt
		total.linkCnt += stats.linkCnt
		total.brokenCnt += stats.brokenCnt
		if stats.cscaCnt > 0 {
			countriesWithCscaCnt++
		}
		if stats.linkCnt > 0 {
			countriesWithLinkCnt++
		}
	}

	printSummary(w, total, countriesWithCscaCnt, countriesWithLinkCnt)
}

func main() { os.Exit(realMain(os.Stdout, os.Stderr)) }

func realMain(w, errW io.Writer) int {
	fmt.Fprintf(w, "GMRTD:v%s\n\n", version.Version)

	deMasterList, err := germanMasterListFn()
	if err != nil {
		fmt.Fprintf(errW, "error loading German master list: %v\n", err)
		return 1
	}

	nlMasterList, err := dutchMasterListFn()
	if err != nil {
		fmt.Fprintf(errW, "error loading Dutch master list: %v\n", err)
		return 1
	}

	idnCerts, err := indonesian2010SeriesCertsFn()
	if err != nil {
		fmt.Fprintf(errW, "error loading Indonesian 2010-series certs: %v\n", err)
		return 1
	}

	pools := []namedPool{
		{name: "DE", pool: deMasterList},
		{name: "NL", pool: nlMasterList},
		{name: "IDN-2010", pool: idnCerts},
	}

	sortedCountries := make([]iso3166.Country, len(iso3166.Countries))
	copy(sortedCountries, iso3166.Countries)
	sort.Slice(sortedCountries, func(i, j int) bool {
		return sortedCountries[i].Alpha2 < sortedCountries[j].Alpha2
	})

	run(pools, sortedCountries, w)
	return 0
}
