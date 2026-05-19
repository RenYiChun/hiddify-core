package hcore

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/hiddify/hiddify-core/v2/config"
)

const (
	geositeCNRuleSetTag           = "geosite-cn"
	countryRuleSetRefreshInterval = 5 * 24 * time.Hour
	maxRuleSetDownloadSize        = 8 * 1024 * 1024
	minRuleSetDownloadSize        = 1024
)

var (
	geositeCNRuleSetURL = "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/country/geosite-cn.srs"

	countryRuleSetRefreshRetryDelays = []time.Duration{
		30 * time.Second,
		1 * time.Minute,
		2 * time.Minute,
		5 * time.Minute,
		10 * time.Minute,
	}
)

//go:embed assets/rule-set/country/geosite-cn.srs
var embeddedGeositeCNRuleSet []byte

func ensureEmbeddedRuleSetFiles() error {
	if sWorkingPath == "" {
		return nil
	}
	return ensureEmbeddedRuleSetFile(
		config.DefaultCountryRuleSetPath(sWorkingPath, geositeCNRuleSetTag),
		embeddedGeositeCNRuleSet,
	)
}

func refreshEmbeddedRuleSetFilesWithRetry() {
	if sWorkingPath == "" {
		return
	}
	path := config.DefaultCountryRuleSetPath(sWorkingPath, geositeCNRuleSetTag)
	if !shouldRefreshRuleSetFile(path, embeddedGeositeCNRuleSet, countryRuleSetRefreshInterval) {
		return
	}
	for attempt, delay := range countryRuleSetRefreshRetryDelays {
		time.Sleep(delay)
		if !shouldRefreshRuleSetFile(path, embeddedGeositeCNRuleSet, countryRuleSetRefreshInterval) {
			return
		}
		if err := refreshEmbeddedRuleSetFiles(); err != nil {
			Log(LogLevel_DEBUG, LogType_CORE, "refresh geosite-cn rule-set attempt ", attempt+1, " failed: ", err)
			continue
		}
		Log(LogLevel_INFO, LogType_CORE, "refreshed geosite-cn rule-set cache")
		return
	}
}

func refreshEmbeddedRuleSetFiles() error {
	if sWorkingPath == "" {
		return nil
	}
	path := config.DefaultCountryRuleSetPath(sWorkingPath, geositeCNRuleSetTag)
	if !shouldRefreshRuleSetFile(path, embeddedGeositeCNRuleSet, countryRuleSetRefreshInterval) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return refreshRuleSetFile(ctx, path, geositeCNRuleSetURL)
}

func ensureEmbeddedRuleSetFile(path string, content []byte) error {
	if len(content) == 0 {
		return nil
	}
	if info, err := os.Stat(path); err == nil && !info.IsDir() && info.Size() > 0 {
		return nil
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o644)
}

func shouldRefreshRuleSetFile(path string, embeddedContent []byte, refreshInterval time.Duration) bool {
	content, err := os.ReadFile(path)
	if err != nil || len(content) == 0 {
		return true
	}
	if bytes.Equal(content, embeddedContent) {
		return true
	}
	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	return time.Since(info.ModTime()) >= refreshInterval
}

func refreshRuleSetFile(ctx context.Context, path string, url string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %s", response.Status)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, maxRuleSetDownloadSize+1))
	if err != nil {
		return err
	}
	if len(content) > maxRuleSetDownloadSize {
		return fmt.Errorf("rule-set download is too large: %d bytes", len(content))
	}
	if len(content) < minRuleSetDownloadSize {
		return fmt.Errorf("rule-set download is too small: %d bytes", len(content))
	}
	return replaceRuleSetFile(path, content)
}

func replaceRuleSetFile(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, content, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err == nil {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}
