package cms

import (
	"encoding/asn1"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCRLFetcherBasic(t *testing.T) {
	fetcher := NewCRLFetcher()
	if fetcher == nil {
		t.Fatal("NewCRLFetcher returned nil")
	}

	if fetcher.client == nil {
		t.Fatal("CRLFetcher client is nil")
	}

	if fetcher.cache == nil {
		t.Fatal("CRLFetcher cache is nil")
	}
}

func TestFetchCRLWithMockServer(t *testing.T) {
	// Create a test CRL (using the NLD CRL data from crl_test.go)
	crlData := nld_clr

	// Create a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crlData)
	}))
	defer server.Close()

	fetcher := NewCRLFetcher()

	// Fetch CRL from mock server
	crl, err := fetcher.FetchCRL(server.URL)
	if err != nil {
		t.Fatalf("FetchCRL failed: %v", err)
	}

	if crl == nil {
		t.Fatal("FetchCRL returned nil CRL")
	}

	// Verify CRL is cached
	if len(fetcher.cache) != 1 {
		t.Fatalf("expected 1 cached CRL, got %d", len(fetcher.cache))
	}

	// Fetch again - should use cache
	crl2, err := fetcher.FetchCRL(server.URL)
	if err != nil {
		t.Fatalf("FetchCRL (cached) failed: %v", err)
	}

	if crl2 != crl {
		t.Fatal("expected cached CRL to be returned")
	}
}

func TestFetchCRLHTTPError(t *testing.T) {
	// Create a mock HTTP server that returns 404
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	fetcher := NewCRLFetcher()

	// Fetch CRL from mock server - should fail
	_, err := fetcher.FetchCRL(server.URL)
	if err == nil {
		t.Fatal("expected FetchCRL to fail with HTTP 404")
	}
}

func TestFetchCRLInvalidData(t *testing.T) {
	// Create a mock HTTP server that returns invalid data
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid CRL data"))
	}))
	defer server.Close()

	fetcher := NewCRLFetcher()

	// Fetch CRL from mock server - should fail to parse
	_, err := fetcher.FetchCRL(server.URL)
	if err == nil {
		t.Fatal("expected FetchCRL to fail with invalid data")
	}
}

func TestCRLCacheExpiration(t *testing.T) {
	// Create a test CRL with a very short NextUpdate time
	crlData := nld_clr

	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		w.Write(crlData)
	}))
	defer server.Close()

	fetcher := NewCRLFetcher()

	// First fetch
	crl1, err := fetcher.FetchCRL(server.URL)
	if err != nil {
		t.Fatalf("FetchCRL failed: %v", err)
	}

	if callCount != 1 {
		t.Fatalf("expected 1 HTTP call, got %d", callCount)
	}

	// Get NextUpdate time
	var nextUpdate time.Time
	if len(crl1.TBSCertList.NextUpdate.FullBytes) > 0 {
		asn1.Unmarshal(crl1.TBSCertList.NextUpdate.FullBytes, &nextUpdate)
	}

	// Second fetch before expiration - should use cache
	crl2, err := fetcher.FetchCRL(server.URL)
	if err != nil {
		t.Fatalf("FetchCRL (cached) failed: %v", err)
	}

	if callCount != 1 {
		t.Fatalf("expected still 1 HTTP call (cached), got %d", callCount)
	}

	if crl2 != crl1 {
		t.Fatal("expected cached CRL to be returned")
	}

	// Manually expire the cache
	fetcher.mu.Lock()
	fetcher.cache[server.URL].NextUpdate = time.Now().Add(-1 * time.Second)
	fetcher.mu.Unlock()

	// Third fetch after expiration - should fetch again
	crl3, err := fetcher.FetchCRL(server.URL)
	if err != nil {
		t.Fatalf("FetchCRL (after expiration) failed: %v", err)
	}

	if callCount != 2 {
		t.Fatalf("expected 2 HTTP calls (expired), got %d", callCount)
	}

	if crl3 == nil {
		t.Fatal("expected new CRL after cache expiration")
	}
}

func TestClearCache(t *testing.T) {
	crlData := nld_clr

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crlData)
	}))
	defer server.Close()

	fetcher := NewCRLFetcher()

	// Fetch CRL
	_, err := fetcher.FetchCRL(server.URL)
	if err != nil {
		t.Fatalf("FetchCRL failed: %v", err)
	}

	if len(fetcher.cache) != 1 {
		t.Fatalf("expected 1 cached CRL, got %d", len(fetcher.cache))
	}

	// Clear cache
	fetcher.ClearCache()

	if len(fetcher.cache) != 0 {
		t.Fatalf("expected 0 cached CRLs after clear, got %d", len(fetcher.cache))
	}
}

func TestClearExpiredCache(t *testing.T) {
	crlData := nld_clr

	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crlData)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crlData)
	}))
	defer server2.Close()

	fetcher := NewCRLFetcher()

	// Fetch from both servers
	_, err := fetcher.FetchCRL(server1.URL)
	if err != nil {
		t.Fatalf("FetchCRL (server1) failed: %v", err)
	}

	_, err = fetcher.FetchCRL(server2.URL)
	if err != nil {
		t.Fatalf("FetchCRL (server2) failed: %v", err)
	}

	if len(fetcher.cache) != 2 {
		t.Fatalf("expected 2 cached CRLs, got %d", len(fetcher.cache))
	}

	// Expire one of them
	fetcher.mu.Lock()
	fetcher.cache[server1.URL].NextUpdate = time.Now().Add(-1 * time.Second)
	fetcher.mu.Unlock()

	// Clear expired
	fetcher.ClearExpiredCache()

	if len(fetcher.cache) != 1 {
		t.Fatalf("expected 1 cached CRL after clearing expired, got %d", len(fetcher.cache))
	}

	// Verify the non-expired one is still there
	fetcher.mu.RLock()
	_, exists := fetcher.cache[server2.URL]
	fetcher.mu.RUnlock()

	if !exists {
		t.Fatal("expected non-expired cache entry to still exist")
	}
}

func TestFetchCRLServerUnavailable(t *testing.T) {
	fetcher := NewCRLFetcher()

	// Try to fetch from a URL that doesn't exist (invalid host)
	_, err := fetcher.FetchCRL("http://invalid-host-that-does-not-exist-12345.com/crl")
	if err == nil {
		t.Fatal("expected FetchCRL to fail when server is unavailable")
	}

	// Verify error message indicates failure to fetch
	if err != nil {
		t.Logf("Got expected error: %v", err)
	}

	// Verify nothing was cached
	if len(fetcher.cache) != 0 {
		t.Fatalf("expected 0 cached CRLs when fetch fails, got %d", len(fetcher.cache))
	}
}
