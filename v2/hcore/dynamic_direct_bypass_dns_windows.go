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
	return dynamicDirectBypassCandidatesFromDNSCacheEntries(entries, suffixes), nil
}

func dynamicDirectBypassCandidatesFromDNSCacheEntries(
	entries []windowsDynamicDirectBypassDNSCacheEntry,
	suffixes []string,
) []dynamicDirectBypassCandidate {
	suffixes = normalizeDynamicDirectBypassSuffixes(suffixes)
	if len(suffixes) == 0 {
		return nil
	}
	hosts := map[string]map[netip.Addr]struct{}{}
	cnames := map[string][]string{}
	for _, entry := range entries {
		host := normalizeDynamicDirectBypassHost(entry.Entry)
		if host == "" {
			continue
		}
		data := strings.TrimSpace(entry.Data)
		if ip, err := netip.ParseAddr(data); err == nil {
			if !isDynamicDirectBypassRouteIP(ip, nil) {
				continue
			}
			if hosts[host] == nil {
				hosts[host] = map[netip.Addr]struct{}{}
			}
			hosts[host][ip] = struct{}{}
			continue
		}
		target := normalizeDynamicDirectBypassHost(data)
		if target == "" {
			continue
		}
		cnames[host] = append(cnames[host], target)
	}
	candidates := make([]dynamicDirectBypassCandidate, 0, len(hosts)+len(cnames))
	for host := range eagerDNSCacheHosts(hosts, cnames, suffixes) {
		ips := collectDNSCacheHostIPs(host, hosts, cnames, map[string]struct{}{})
		sortAddrSlice(ips)
		candidates = append(candidates, dynamicDirectBypassCandidate{Host: host, IPs: ips})
	}
	sortDynamicDirectBypassCandidates(candidates)
	return candidates
}

func eagerDNSCacheHosts(
	hosts map[string]map[netip.Addr]struct{},
	cnames map[string][]string,
	suffixes []string,
) map[string]struct{} {
	result := map[string]struct{}{}
	for host := range hosts {
		if matchesDynamicDirectBypassSuffix(host, suffixes) {
			result[host] = struct{}{}
		}
	}
	for host := range cnames {
		if matchesDynamicDirectBypassSuffix(host, suffixes) {
			result[host] = struct{}{}
		}
	}
	return result
}

func collectDNSCacheHostIPs(
	host string,
	hosts map[string]map[netip.Addr]struct{},
	cnames map[string][]string,
	visited map[string]struct{},
) []netip.Addr {
	if _, exists := visited[host]; exists {
		return nil
	}
	visited[host] = struct{}{}
	seen := map[netip.Addr]struct{}{}
	for ip := range hosts[host] {
		seen[ip] = struct{}{}
	}
	for _, target := range cnames[host] {
		for _, ip := range collectDNSCacheHostIPs(target, hosts, cnames, visited) {
			seen[ip] = struct{}{}
		}
	}
	ips := make([]netip.Addr, 0, len(seen))
	for ip := range seen {
		ips = append(ips, ip)
	}
	return ips
}

func windowsDNSCacheDiscoveryScript() string {
	return `ConvertTo-Json -InputObject @(Get-DnsClientCache | ` +
		`Where-Object { $_.Status -eq 0 -and $_.Data } | ` +
		`Select-Object Entry, Data) -Compress`
}
