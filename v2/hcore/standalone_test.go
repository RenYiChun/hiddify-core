package hcore

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestApplyStandaloneExperimentalOptionsPreservesMonitoringOptions(t *testing.T) {
	hopts := config.DefaultHiddifyOptions()
	hopts.AllowConnectionFromLAN = false
	hopts.ConnectionTestUrls = []string{
		"https://www.google.com/generate_204",
		"https://github.com",
	}
	options := &option.Options{
		Experimental: &option.ExperimentalOptions{
			UnifiedDelay: &option.UnifiedDelayOptions{Enabled: true},
			CacheFile:    &option.CacheFileOptions{Enabled: true, Path: "data/clash.db"},
			Monitoring: &option.MonitoringOptions{
				URLs:           hopts.ConnectionTestUrls,
				Interval:       badoption.Duration(10 * time.Second),
				DebounceWindow: badoption.Duration(500 * time.Millisecond),
			},
		},
	}

	applyStandaloneExperimentalOptions(options, hopts)

	if options.Experimental == nil {
		t.Fatal("expected experimental options")
	}
	if options.Experimental.Monitoring == nil {
		t.Fatal("expected standalone config to preserve monitoring options")
	}
	urls := strings.Join(options.Experimental.Monitoring.URLs, "\n")
	for _, want := range hopts.ConnectionTestUrls {
		if !strings.Contains(urls, want) {
			t.Fatalf("expected monitoring URLs to include %q, got %v", want, options.Experimental.Monitoring.URLs)
		}
	}
	if options.Experimental.UnifiedDelay == nil || !options.Experimental.UnifiedDelay.Enabled {
		t.Fatal("expected standalone config to preserve unified delay")
	}
	if options.Experimental.CacheFile == nil || !options.Experimental.CacheFile.Enabled {
		t.Fatal("expected standalone config to preserve cache file")
	}
	if options.Experimental.ClashAPI == nil {
		t.Fatal("expected standalone config to configure clash api")
	}
	if options.Experimental.ClashAPI.ExternalController != "127.0.0.1:16756" {
		t.Fatalf("expected loopback clash controller, got %q", options.Experimental.ClashAPI.ExternalController)
	}
}

func TestApplyLocalDirectDomainSuffixRulesPathUsesWorkingPath(t *testing.T) {
	previousWorkingPath := sWorkingPath
	sWorkingPath = t.TempDir()
	t.Cleanup(func() {
		sWorkingPath = previousWorkingPath
	})

	hopts := config.DefaultHiddifyOptions()
	applyLocalDirectDomainSuffixRulesPath(hopts)

	expected := filepath.Clean(config.DefaultDirectDomainSuffixRulesPath(sWorkingPath))
	if hopts.DirectDomainSuffixRulesPath != expected {
		t.Fatalf("expected direct domain suffix rules path %q, got %q", expected, hopts.DirectDomainSuffixRulesPath)
	}
}

func TestApplyLocalDirectDomainSuffixRulesPathKeepsExplicitPath(t *testing.T) {
	previousWorkingPath := sWorkingPath
	sWorkingPath = t.TempDir()
	t.Cleanup(func() {
		sWorkingPath = previousWorkingPath
	})

	hopts := config.DefaultHiddifyOptions()
	hopts.DirectDomainSuffixRulesPath = filepath.Join(t.TempDir(), "custom-rules.txt")
	applyLocalDirectDomainSuffixRulesPath(hopts)

	if filepath.Base(hopts.DirectDomainSuffixRulesPath) != "custom-rules.txt" {
		t.Fatalf("expected explicit rules path to be preserved, got %q", hopts.DirectDomainSuffixRulesPath)
	}
}
