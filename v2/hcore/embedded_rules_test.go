package hcore

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hiddify/hiddify-core/v2/config"
)

func TestEnsureEmbeddedRuleSetFilesWritesGeositeCN(t *testing.T) {
	previousWorkingPath := sWorkingPath
	sWorkingPath = t.TempDir()
	defer func() {
		sWorkingPath = previousWorkingPath
	}()

	if err := ensureEmbeddedRuleSetFiles(); err != nil {
		t.Fatal(err)
	}

	path := config.DefaultCountryRuleSetPath(sWorkingPath, "geosite-cn")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Fatal("expected embedded geosite-cn rule-set to be written")
	}
}

func TestEnsureEmbeddedRuleSetFilesPreservesExistingGeositeCN(t *testing.T) {
	previousWorkingPath := sWorkingPath
	sWorkingPath = t.TempDir()
	defer func() {
		sWorkingPath = previousWorkingPath
	}()

	path := config.DefaultCountryRuleSetPath(sWorkingPath, "geosite-cn")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	existing := []byte("existing")
	if err := os.WriteFile(path, existing, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := ensureEmbeddedRuleSetFiles(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, existing) {
		t.Fatalf("expected existing geosite-cn rule-set to be preserved, got %q", string(content))
	}
}

func TestShouldRefreshRuleSetFileRefreshesEmbeddedSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geosite-cn.srs")
	if err := os.WriteFile(path, embeddedGeositeCNRuleSet, 0o644); err != nil {
		t.Fatal(err)
	}

	if !shouldRefreshRuleSetFile(path, embeddedGeositeCNRuleSet, countryRuleSetRefreshInterval) {
		t.Fatal("expected embedded seed rule-set to be refreshed")
	}
}

func TestShouldRefreshRuleSetFileKeepsFreshUpdatedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geosite-cn.srs")
	if err := os.WriteFile(path, []byte("updated"), 0o644); err != nil {
		t.Fatal(err)
	}

	if shouldRefreshRuleSetFile(path, embeddedGeositeCNRuleSet, countryRuleSetRefreshInterval) {
		t.Fatal("expected fresh non-embedded rule-set to be kept")
	}
}

func TestShouldRefreshRuleSetFileRefreshesStaleUpdatedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geosite-cn.srs")
	if err := os.WriteFile(path, []byte("updated"), 0o644); err != nil {
		t.Fatal(err)
	}
	staleTime := time.Now().Add(-countryRuleSetRefreshInterval - time.Hour)
	if err := os.Chtimes(path, staleTime, staleTime); err != nil {
		t.Fatal(err)
	}

	if !shouldRefreshRuleSetFile(path, embeddedGeositeCNRuleSet, countryRuleSetRefreshInterval) {
		t.Fatal("expected stale non-embedded rule-set to be refreshed")
	}
}

func TestRefreshRuleSetFileDownloadsAndReplaces(t *testing.T) {
	content := bytes.Repeat([]byte{1, 2, 3, 4}, 512)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "rules", "geosite-cn.srs")
	if err := refreshRuleSetFile(context.Background(), path, server.URL); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("expected downloaded rule-set content to be written")
	}
}

func TestRefreshRuleSetFileKeepsExistingFileOnInvalidDownload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("too small"))
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "rules", "geosite-cn.srs")
	existing := []byte("existing")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, existing, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := refreshRuleSetFile(context.Background(), path, server.URL); err == nil {
		t.Fatal("expected invalid download to fail")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, existing) {
		t.Fatal("expected existing rule-set to be kept when refresh fails")
	}
}

func TestRefreshEmbeddedRuleSetFilesReturnsAfterSuccessfulDownload(t *testing.T) {
	previousWorkingPath := sWorkingPath
	sWorkingPath = t.TempDir()
	defer func() {
		sWorkingPath = previousWorkingPath
	}()
	previousURL := geositeCNRuleSetURL
	content := bytes.Repeat([]byte{5, 6, 7, 8}, 512)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer server.Close()
	geositeCNRuleSetURL = server.URL
	defer func() {
		geositeCNRuleSetURL = previousURL
	}()

	if err := ensureEmbeddedRuleSetFiles(); err != nil {
		t.Fatal(err)
	}
	if err := refreshEmbeddedRuleSetFiles(); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(config.DefaultCountryRuleSetPath(sWorkingPath, geositeCNRuleSetTag))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("expected refreshed rule-set content")
	}
}
