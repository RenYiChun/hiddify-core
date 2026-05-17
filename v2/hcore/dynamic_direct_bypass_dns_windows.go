//go:build windows

package hcore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
)

type windowsDynamicDirectBypassDNSCacheReader struct{}

type windowsDynamicDirectBypassDNSCacheEntry struct {
	Entry string `json:"Entry"`
	Data  string `json:"Data"`
}

func newSystemDynamicDirectBypassDNSCacheReader() dynamicDirectBypassDNSCacheReader {
	return windowsDynamicDirectBypassDNSCacheReader{}
}

func (windowsDynamicDirectBypassDNSCacheReader) LookupCachedHostIPs(
	ctx context.Context,
	suffixes []string,
) ([]dynamicDirectBypassCandidate, error) {
	suffixes = normalizeDynamicDirectBypassSuffixes(suffixes)
	if len(suffixes) == 0 {
		return nil, nil
	}
	cmd, cancel := newHiddenDynamicDirectBypassCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", windowsDNSCacheDiscoveryScript())
	defer cancel()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("discover dns cache failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var entries []windowsDynamicDirectBypassDNSCacheEntry
	if err := json.Unmarshal(bytes.TrimSpace(output), &entries); err != nil {
		return nil, fmt.Errorf("parse dns cache failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	hosts := map[string]map[netip.Addr]struct{}{}
	for _, entry := range entries {
		host := normalizeDynamicDirectBypassHost(entry.Entry)
		if host == "" || !matchesDynamicDirectBypassSuffix(host, suffixes) {
			continue
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(entry.Data))
		if err != nil || !isDynamicDirectBypassRouteIP(ip, nil) {
			continue
		}
		if hosts[host] == nil {
			hosts[host] = map[netip.Addr]struct{}{}
		}
		hosts[host][ip] = struct{}{}
	}
	candidates := make([]dynamicDirectBypassCandidate, 0, len(hosts))
	for host, hostIPs := range hosts {
		ips := make([]netip.Addr, 0, len(hostIPs))
		for ip := range hostIPs {
			ips = append(ips, ip)
		}
		sortAddrSlice(ips)
		candidates = append(candidates, dynamicDirectBypassCandidate{Host: host, IPs: ips})
	}
	sortDynamicDirectBypassCandidates(candidates)
	return candidates, nil
}

func windowsDNSCacheDiscoveryScript() string {
	return `ConvertTo-Json -InputObject @(Get-DnsClientCache | ` +
		`Where-Object { $_.Status -eq 0 -and $_.Data -match '^\d{1,3}(\.\d{1,3}){3}$' } | ` +
		`Select-Object Entry, Data) -Compress`
}
