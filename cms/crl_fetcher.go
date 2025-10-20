package cms

import (
	"encoding/asn1"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// CRLCache stores a CRL with its expiration time
type CRLCache struct {
	CRL        *CertificateList
	NextUpdate time.Time
}

// CRLFetcher handles fetching and caching of CRLs
type CRLFetcher struct {
	client *http.Client
	cache  map[string]*CRLCache
	mu     sync.RWMutex
}

// NewCRLFetcher creates a new CRL fetcher with a default HTTP client
func NewCRLFetcher() *CRLFetcher {
	return &CRLFetcher{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache: make(map[string]*CRLCache),
	}
}

// FetchCRL fetches a CRL from the given URL, using cache if available and not expired
func (f *CRLFetcher) FetchCRL(url string) (*CertificateList, error) {
	// Check cache first
	f.mu.RLock()
	cached, exists := f.cache[url]
	f.mu.RUnlock()

	if exists && time.Now().Before(cached.NextUpdate) {
		return cached.CRL, nil
	}

	// Fetch from URL
	resp, err := f.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CRL from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch CRL from %s: HTTP %d", url, resp.StatusCode)
	}

	// Read response body
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL response from %s: %w", url, err)
	}

	// Parse CRL
	crl, err := ParseCertificateRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL from %s: %w", url, err)
	}

	// Extract NextUpdate time for caching
	var nextUpdate time.Time
	if len(crl.TBSCertList.NextUpdate.FullBytes) > 0 {
		if _, err := asn1.Unmarshal(crl.TBSCertList.NextUpdate.FullBytes, &nextUpdate); err != nil {
			// If we can't parse NextUpdate, cache for 1 hour as fallback
			nextUpdate = time.Now().Add(1 * time.Hour)
		}
	} else {
		// No NextUpdate field, cache for 1 hour as fallback
		nextUpdate = time.Now().Add(1 * time.Hour)
	}

	// Store in cache
	f.mu.Lock()
	f.cache[url] = &CRLCache{
		CRL:        crl,
		NextUpdate: nextUpdate,
	}
	f.mu.Unlock()

	return crl, nil
}

// ClearCache removes all cached CRLs
func (f *CRLFetcher) ClearCache() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cache = make(map[string]*CRLCache)
}

// ClearExpiredCache removes expired CRLs from cache
func (f *CRLFetcher) ClearExpiredCache() {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := time.Now()
	for url, cached := range f.cache {
		if now.After(cached.NextUpdate) {
			delete(f.cache, url)
		}
	}
}

// SetCRL sets a CRL in the cache for a given URL (primarily for testing)
func (f *CRLFetcher) SetCRL(url string, crl *CertificateList, nextUpdate time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cache[url] = &CRLCache{
		CRL:        crl,
		NextUpdate: nextUpdate,
	}
}
