package hcore

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

type fakeDynamicDirectBypassRouteManager struct {
	added   []netip.Addr
	deleted []netip.Addr
}

type fakeDynamicDirectBypassResolver map[string][]netip.Addr
type fakeDynamicDirectBypassDNSCacheReader []dynamicDirectBypassCandidate

func (f *fakeDynamicDirectBypassRouteManager) AddHostRoute(_ context.Context, addr netip.Addr) error {
	f.added = append(f.added, addr)
	return nil
}

func (f *fakeDynamicDirectBypassRouteManager) DeleteHostRoute(_ context.Context, addr netip.Addr) error {
	f.deleted = append(f.deleted, addr)
	return nil
}

func (f fakeDynamicDirectBypassResolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	return f[host], nil
}

func (f fakeDynamicDirectBypassDNSCacheReader) LookupCachedHostIPs(
	_ context.Context,
	_ []string,
) ([]dynamicDirectBypassCandidate, error) {
	return []dynamicDirectBypassCandidate(f), nil
}

func TestSelectDynamicDirectBypassCandidatesSelectsHotDirectHost(t *testing.T) {
	cfg := dynamicDirectBypassConfig{
		Enabled:          true,
		MaxRoutesPerHost: 4,
	}
	connections := []dynamicDirectBypassConnection{
		hotDirectConnection("cube.weixinbridge.com", "101.226.99.155"),
		hotDirectConnection("cube.weixinbridge.com", "101.226.99.155"),
		hotDirectConnection("cube.weixinbridge.com", "101.226.99.156"),
	}

	candidates := selectDynamicDirectBypassCandidates(connections, cfg, nil)

	if len(candidates) != 1 {
		t.Fatalf("expected one dynamic bypass candidate, got %#v", candidates)
	}
	if candidates[0].Host != "cube.weixinbridge.com" {
		t.Fatalf("unexpected candidate host: %s", candidates[0].Host)
	}
	if !containsAddr(candidates[0].IPs, netip.MustParseAddr("101.226.99.155")) ||
		!containsAddr(candidates[0].IPs, netip.MustParseAddr("101.226.99.156")) {
		t.Fatalf("expected observed public IPs in candidate, got %#v", candidates[0].IPs)
	}
}

func TestSelectDynamicDirectBypassCandidatesSelectsEveryDirectDestination(t *testing.T) {
	cfg := dynamicDirectBypassConfig{
		Enabled:          true,
		MaxRoutesPerHost: 4,
	}
	connections := []dynamicDirectBypassConnection{
		hotDirectConnection("low.example.cn", "101.226.99.155"),
		{
			Destination:  netip.MustParseAddr("93.184.216.34"),
			Outbound:     "direct §hide§",
			OutboundType: "direct",
			Chain:        []string{"direct §hide§"},
		},
		{
			Host:         "proxied.example.com",
			Destination:  netip.MustParseAddr("140.82.112.4"),
			Outbound:     "select",
			OutboundType: "vmess",
			Chain:        []string{"select", "proxy"},
		},
	}

	candidates := selectDynamicDirectBypassCandidates(connections, cfg, nil)

	if len(candidates) != 2 {
		t.Fatalf("expected two direct dynamic bypass candidates, got %#v", candidates)
	}
	if candidates[0].Host != "93.184.216.34" || !containsAddr(candidates[0].IPs, netip.MustParseAddr("93.184.216.34")) {
		t.Fatalf("expected hostless direct destination candidate, got %#v", candidates[0])
	}
	if candidates[1].Host != "low.example.cn" || !containsAddr(candidates[1].IPs, netip.MustParseAddr("101.226.99.155")) {
		t.Fatalf("expected low-count direct host candidate, got %#v", candidates[1])
	}
}

func TestSelectDynamicDirectBypassCandidatesIgnoresUnsafeProtectedAndNonDirectTraffic(t *testing.T) {
	cfg := dynamicDirectBypassConfig{
		Enabled:          true,
		MaxRoutesPerHost: 4,
	}
	protected := map[netip.Addr]struct{}{
		netip.MustParseAddr("8.8.8.8"): {},
	}
	connections := []dynamicDirectBypassConnection{
		hotDirectConnection("low.example.cn", "101.226.99.155"),
		hotDirectConnection("private.example.cn", "192.168.3.10"),
		hotDirectConnection("protected.example.cn", "8.8.8.8"),
		{
			Host:         "proxied.example.com",
			Destination:  netip.MustParseAddr("93.184.216.34"),
			Outbound:     "select",
			OutboundType: "vmess",
			Chain:        []string{"select", "proxy"},
		},
		{
			Host:         "proxied.example.com",
			Destination:  netip.MustParseAddr("93.184.216.34"),
			Outbound:     "select",
			OutboundType: "vmess",
			Chain:        []string{"select", "proxy"},
		},
	}

	candidates := selectDynamicDirectBypassCandidates(connections, cfg, protected)

	if len(candidates) != 1 {
		t.Fatalf("expected only the routeable direct candidate, got %#v", candidates)
	}
	if candidates[0].Host != "low.example.cn" || !containsAddr(candidates[0].IPs, netip.MustParseAddr("101.226.99.155")) {
		t.Fatalf("expected low-count public direct traffic to be selected, got %#v", candidates[0])
	}
}

func TestSelectDynamicDirectBypassCandidatesEagerSuffixDoesNotWaitForHotThreshold(t *testing.T) {
	cfg := dynamicDirectBypassConfig{
		Enabled:          true,
		MaxRoutesPerHost: 4,
		EagerSuffixes:    []string{"myqcloud.com"},
	}
	connections := []dynamicDirectBypassConnection{
		hotDirectConnection("wework-weipan-1258344707.cos.ap-guangzhou.myqcloud.com", "183.60.116.3"),
	}

	candidates := selectDynamicDirectBypassCandidates(connections, cfg, nil)

	if len(candidates) != 1 {
		t.Fatalf("expected eager direct suffix candidate, got %#v", candidates)
	}
	if candidates[0].Host != "wework-weipan-1258344707.cos.ap-guangzhou.myqcloud.com" {
		t.Fatalf("unexpected candidate host: %s", candidates[0].Host)
	}
	if !containsAddr(candidates[0].IPs, netip.MustParseAddr("183.60.116.3")) {
		t.Fatalf("expected observed COS IP in candidate, got %#v", candidates[0].IPs)
	}
}

func TestSelectDynamicDirectBypassCandidatesDoesNotTreatProxyTagContainingDirectAsDirect(t *testing.T) {
	cfg := dynamicDirectBypassConfig{
		Enabled:          true,
		MaxRoutesPerHost: 4,
	}
	connections := []dynamicDirectBypassConnection{
		{
			Host:         "github.com",
			Destination:  netip.MustParseAddr("140.82.112.4"),
			Outbound:     "209.87.93.20 tls_h2 grpc direct vless § 443 1",
			OutboundType: "vless",
			Chain:        []string{"select", "209.87.93.20 tls_h2 grpc direct vless § 443 1"},
		},
		{
			Host:         "github.com",
			Destination:  netip.MustParseAddr("140.82.112.4"),
			Outbound:     "209.87.93.20 tls_h2 grpc direct vless § 443 1",
			OutboundType: "vless",
			Chain:        []string{"select", "209.87.93.20 tls_h2 grpc direct vless § 443 1"},
		},
	}

	candidates := selectDynamicDirectBypassCandidates(connections, cfg, nil)

	if len(candidates) != 0 {
		t.Fatalf("expected proxy node tag containing direct not to be bypassed, got %#v", candidates)
	}
}

func TestDynamicDirectBypassManagerAppliesRoutesOnceAndExpiresThem(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, nil, nil, "")
	candidate := dynamicDirectBypassCandidate{
		Host: "cube.weixinbridge.com",
		IPs:  []netip.Addr{netip.MustParseAddr("101.226.99.155")},
	}

	manager.applyCandidates(context.Background(), []dynamicDirectBypassCandidate{candidate}, now)
	manager.applyCandidates(context.Background(), []dynamicDirectBypassCandidate{candidate}, now.Add(time.Minute))

	if len(routeManager.added) != 1 {
		t.Fatalf("expected route to be added once, got %d additions: %#v", len(routeManager.added), routeManager.added)
	}

	manager.cleanupExpired(context.Background(), now.Add(6*time.Minute))

	if len(routeManager.deleted) != 1 {
		t.Fatalf("expected expired route to be deleted once, got %d deletions: %#v", len(routeManager.deleted), routeManager.deleted)
	}
}

func TestDynamicDirectBypassManagerRefreshesExistingRouteAtMaxRoutes(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        1,
		MaxRoutesPerHost: 4,
	}, routeManager, nil, nil, "")
	candidate := dynamicDirectBypassCandidate{
		Host: "cube.weixinbridge.com",
		IPs:  []netip.Addr{netip.MustParseAddr("101.226.99.155")},
	}

	manager.applyCandidates(context.Background(), []dynamicDirectBypassCandidate{candidate}, now)
	manager.applyCandidates(context.Background(), []dynamicDirectBypassCandidate{candidate}, now.Add(time.Minute))
	manager.cleanupExpired(context.Background(), now.Add(5*time.Minute+30*time.Second))

	if len(routeManager.deleted) != 0 {
		t.Fatalf("expected refreshed route to remain active at max routes, got deletions: %#v", routeManager.deleted)
	}
}

func TestDynamicDirectBypassManagerPreservesCacheOnCloseAndDeletesRoutes(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, nil, nil, cachePath)
	candidate := dynamicDirectBypassCandidate{
		Host: "cube.weixinbridge.com",
		IPs:  []netip.Addr{netip.MustParseAddr("101.226.99.155")},
	}

	manager.applyCandidates(context.Background(), []dynamicDirectBypassCandidate{candidate}, now)
	manager.close(context.Background())

	if len(routeManager.deleted) != 1 {
		t.Fatalf("expected close to delete active route, got %#v", routeManager.deleted)
	}
	cached := readDynamicDirectBypassCache(t, cachePath)
	if len(cached) != 1 || cached[0].IP != "101.226.99.155" {
		t.Fatalf("expected close to preserve cache for next start, got %#v", cached)
	}
}

func TestDynamicDirectBypassManagerPersistsProcessMetadata(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, nil, nil, cachePath)
	candidates := selectDynamicDirectBypassCandidates([]dynamicDirectBypassConnection{
		{
			Host:         "docs.qq.com",
			Destination:  netip.MustParseAddr("43.154.240.12"),
			Outbound:     "direct §hide§",
			OutboundType: "direct",
			Chain:        []string{"direct §hide§"},
			ProcessPath:  `C:\Program Files\Tencent\WeCom\WXWork.exe`,
		},
	}, manager.config, nil)

	manager.applyCandidates(context.Background(), candidates, now)

	cached := readDynamicDirectBypassCache(t, cachePath)
	if len(cached) != 1 {
		t.Fatalf("expected one cached route, got %#v", cached)
	}
	if cached[0].ProcessName != "WXWork.exe" || cached[0].ProcessPath != `C:\Program Files\Tencent\WeCom\WXWork.exe` {
		t.Fatalf("expected process metadata in cache, got %#v", cached[0])
	}
}

func TestDynamicDirectBypassManagerDeletesExpiredCachedRoutesOnLoad(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	cached := []dynamicDirectBypassRoute{
		{
			Host:      "cube.weixinbridge.com",
			IP:        "101.226.99.155",
			LastSeen:  now.Add(-time.Hour),
			ExpiresAt: now.Add(-time.Minute),
		},
	}
	writeDynamicDirectBypassCache(t, cachePath, cached)
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, nil, nil, cachePath)

	if err := manager.loadCacheAndApply(context.Background(), now); err != nil {
		t.Fatal(err)
	}

	if len(routeManager.deleted) != 1 || routeManager.deleted[0] != netip.MustParseAddr("101.226.99.155") {
		t.Fatalf("expected expired cached route to be deleted, got %#v", routeManager.deleted)
	}
	if cached := readDynamicDirectBypassCache(t, cachePath); len(cached) != 0 {
		t.Fatalf("expected expired cache to be removed, got %#v", cached)
	}
}

func TestCleanupDynamicDirectBypassCachedSystemRoutesDeletesCachedRoutesWithoutStarting(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	writeDynamicDirectBypassCache(t, cachePath, []dynamicDirectBypassRoute{
		{
			Host:      "auth.huaweicloud.com",
			IP:        "117.78.12.125",
			LastSeen:  now,
			ExpiresAt: now.Add(30 * time.Minute),
		},
		{
			Host:      "invalid.example.com",
			IP:        "not-an-ip",
			LastSeen:  now,
			ExpiresAt: now.Add(30 * time.Minute),
		},
	})

	cleanupDynamicDirectBypassCachedSystemRoutes(context.Background(), routeManager, cachePath)

	if len(routeManager.deleted) != 1 || routeManager.deleted[0] != netip.MustParseAddr("117.78.12.125") {
		t.Fatalf("expected cached system route to be deleted, got %#v", routeManager.deleted)
	}
}

func TestDynamicDirectBypassManagerResolvesHotDomainWhenObservedIPIsMissing(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, fakeDynamicDirectBypassResolver{
		"cube.weixinbridge.com": {netip.MustParseAddr("101.226.99.155")},
	}, nil, "")
	connections := []dynamicDirectBypassConnection{
		{
			Host:         "cube.weixinbridge.com",
			Outbound:     "direct §hide§",
			OutboundType: "direct",
			Chain:        []string{"direct §hide§"},
		},
		{
			Host:         "cube.weixinbridge.com",
			Outbound:     "direct §hide§",
			OutboundType: "direct",
			Chain:        []string{"direct §hide§"},
		},
	}

	candidates := selectDynamicDirectBypassCandidates(connections, manager.config, nil)
	manager.applyCandidates(context.Background(), candidates, now)

	if len(routeManager.added) != 1 || routeManager.added[0] != netip.MustParseAddr("101.226.99.155") {
		t.Fatalf("expected resolved IP to be added as a route, got %#v", routeManager.added)
	}
}

func TestDynamicDirectBypassManagerDoesNotResolveObservedNonEagerHost(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, fakeDynamicDirectBypassResolver{
		"docs.qq.com": {
			netip.MustParseAddr("43.154.240.12"),
			netip.MustParseAddr("43.154.240.13"),
		},
	}, nil, "")
	candidate := dynamicDirectBypassCandidate{
		Host: "docs.qq.com",
		IPs:  []netip.Addr{netip.MustParseAddr("43.154.240.12")},
	}

	manager.applyCandidates(context.Background(), []dynamicDirectBypassCandidate{candidate}, now)

	if len(routeManager.added) != 1 || routeManager.added[0] != netip.MustParseAddr("43.154.240.12") {
		t.Fatalf("expected only observed IP to be added, got %#v", routeManager.added)
	}
}

func TestDynamicDirectBypassManagerResolvesObservedEagerHost(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
		EagerSuffixes:    []string{"myqcloud.com"},
	}, routeManager, fakeDynamicDirectBypassResolver{
		"wework-weipan-1258344707.cos.ap-guangzhou.myqcloud.com": {
			netip.MustParseAddr("183.60.116.3"),
			netip.MustParseAddr("183.60.116.4"),
		},
	}, nil, "")
	candidate := dynamicDirectBypassCandidate{
		Host: "wework-weipan-1258344707.cos.ap-guangzhou.myqcloud.com",
		IPs:  []netip.Addr{netip.MustParseAddr("183.60.116.3")},
	}

	manager.applyCandidates(context.Background(), []dynamicDirectBypassCandidate{candidate}, now)

	if len(routeManager.added) != 2 ||
		!containsAddr(routeManager.added, netip.MustParseAddr("183.60.116.3")) ||
		!containsAddr(routeManager.added, netip.MustParseAddr("183.60.116.4")) {
		t.Fatalf("expected eager host to include resolved IPs, got %#v", routeManager.added)
	}
}

func TestDynamicDirectBypassManagerAppliesDNSCacheCandidatesForEagerSuffixes(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
		EagerSuffixes:    []string{"myqcloud.com"},
	}, routeManager, nil, fakeDynamicDirectBypassDNSCacheReader{
		{
			Host: "wework-weipan-1258344707.cos.ap-guangzhou.myqcloud.com",
			IPs:  []netip.Addr{netip.MustParseAddr("183.60.116.3")},
		},
	}, "")

	manager.applyDNSCacheCandidates(context.Background(), now)

	if len(routeManager.added) != 1 || routeManager.added[0] != netip.MustParseAddr("183.60.116.3") {
		t.Fatalf("expected DNS cache IP to be added as a route, got %#v", routeManager.added)
	}
}

func TestDynamicDirectBypassManagerRestoresInitialRoutesOnlyOnce(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	writeDynamicDirectBypassCache(t, cachePath, []dynamicDirectBypassRoute{
		{
			Host:      "auth.huaweicloud.com",
			IP:        "117.78.12.125",
			LastSeen:  now,
			ExpiresAt: now.Add(30 * time.Minute),
		},
	})
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
		EagerSuffixes:    []string{"huaweicloud.com"},
	}, routeManager, nil, fakeDynamicDirectBypassDNSCacheReader{
		{
			Host: "auth.huaweicloud.com",
			IPs:  []netip.Addr{netip.MustParseAddr("49.4.112.125")},
		},
	}, cachePath)

	manager.restoreInitial(context.Background(), now)
	manager.restoreInitial(context.Background(), now.Add(time.Second))

	if len(routeManager.added) != 2 ||
		!containsAddr(routeManager.added, netip.MustParseAddr("117.78.12.125")) ||
		!containsAddr(routeManager.added, netip.MustParseAddr("49.4.112.125")) {
		t.Fatalf("expected cached and DNS routes to be restored once, got %#v", routeManager.added)
	}
}

func TestDynamicDirectBypassConfigFromOptionsReadsCustomValues(t *testing.T) {
	custom := map[string]any{
		customDynamicDirectBypassEnabledKey:       false,
		customDynamicDirectBypassTTLKey:           900,
		customDynamicDirectBypassMaxRoutesKey:     128,
		customDynamicDirectBypassMaxRoutesHostKey: 16,
	}

	config := dynamicDirectBypassConfigFromOptions(option.Options{Custom: &custom})

	if config.Enabled {
		t.Fatal("expected dynamic direct bypass to be disabled from custom option")
	}
	if config.RouteTTL != 15*time.Minute || config.MaxRoutes != 128 || config.MaxRoutesPerHost != 16 {
		t.Fatalf("unexpected dynamic direct bypass config: %#v", config)
	}
}

func TestDefaultDynamicDirectBypassConfigScansConnectionsFasterThanDNSCache(t *testing.T) {
	config := defaultDynamicDirectBypassConfig()

	if config.SampleInterval != time.Second {
		t.Fatalf("expected direct connection scan interval to be 1s, got %s", config.SampleInterval)
	}
	if config.DNSCacheInterval != 5*time.Second {
		t.Fatalf("expected DNS cache scan interval to stay 5s, got %s", config.DNSCacheInterval)
	}
}

func hotDirectConnection(host string, ip string) dynamicDirectBypassConnection {
	return dynamicDirectBypassConnection{
		Host:         host,
		Destination:  netip.MustParseAddr(ip),
		Outbound:     "direct §hide§",
		OutboundType: "direct",
		Chain:        []string{"direct §hide§"},
	}
}

func containsAddr(values []netip.Addr, target netip.Addr) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func readDynamicDirectBypassCache(t *testing.T, path string) []dynamicDirectBypassRoute {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cached []dynamicDirectBypassRoute
	if err := json.Unmarshal(content, &cached); err != nil {
		t.Fatal(err)
	}
	return cached
}

func writeDynamicDirectBypassCache(t *testing.T, path string, cached []dynamicDirectBypassRoute) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	content, err := json.Marshal(cached)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}
