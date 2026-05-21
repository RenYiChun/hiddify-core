//go:build windows

package hcore

import (
	"net/netip"
	"testing"
	"time"
)

func TestWindowsDNSCacheDiscoveryTimeoutAllowsSlowPowerShellStartup(t *testing.T) {
	if windowsDNSCacheDiscoveryTimeout < 15*time.Second {
		t.Fatalf("expected DNS cache discovery timeout to tolerate slow PowerShell startup, got %s", windowsDNSCacheDiscoveryTimeout)
	}
}

func TestWindowsDNSCacheCandidatesFollowCNAMEChainForEagerSuffix(t *testing.T) {
	entries := []windowsDynamicDirectBypassDNSCacheEntry{
		{
			Entry: "ocsp.globalsign.com",
			Data:  "cdn.globalsigncdn.com.cdn.cloudflare.net",
		},
		{
			Entry: "cdn.globalsigncdn.com.cdn.cloudflare.net",
			Data:  "124.225.84.76",
		},
	}

	candidates := dynamicDirectBypassCandidatesFromDNSCacheEntries(entries, []string{"globalsign.com"})

	if len(candidates) != 1 {
		t.Fatalf("expected one eager DNS cache candidate, got %#v", candidates)
	}
	if candidates[0].Host != "ocsp.globalsign.com" {
		t.Fatalf("expected original eager host to be preserved, got %q", candidates[0].Host)
	}
	if !containsAddr(candidates[0].IPs, netip.MustParseAddr("124.225.84.76")) {
		t.Fatalf("expected CNAME target A record to be attached, got %#v", candidates[0].IPs)
	}
}
