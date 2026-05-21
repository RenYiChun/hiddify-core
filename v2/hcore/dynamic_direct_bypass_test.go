package hcore

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type fakeDynamicDirectBypassRouteManager struct {
	added   []netip.Addr
	deleted []netip.Addr
}

type fakeBatchDynamicDirectBypassRouteManager struct {
	fakeDynamicDirectBypassRouteManager
	batchAdded   [][]netip.Addr
	batchDeleted [][]netip.Addr
}

type fakeDynamicDirectBypassResolver map[string][]netip.Addr
type fakeDynamicDirectBypassDNSCacheReader []dynamicDirectBypassCandidate

type fakeDynamicDirectBypassDirectProbe struct {
	err   error
	calls []fakeDynamicDirectBypassDirectProbeCall
}

type fakeDynamicDirectBypassDirectProbeCall struct {
	host string
	ip   netip.Addr
	port uint16
}

func (f *fakeDynamicDirectBypassRouteManager) AddHostRoute(_ context.Context, addr netip.Addr) error {
	f.added = append(f.added, addr)
	return nil
}

func (f *fakeDynamicDirectBypassRouteManager) DeleteHostRoute(_ context.Context, addr netip.Addr) error {
	f.deleted = append(f.deleted, addr)
	return nil
}

func (f *fakeBatchDynamicDirectBypassRouteManager) AddHostRoutes(_ context.Context, addrs []netip.Addr) map[netip.Addr]error {
	f.batchAdded = append(f.batchAdded, append([]netip.Addr(nil), addrs...))
	return nil
}

func (f *fakeBatchDynamicDirectBypassRouteManager) DeleteHostRoutes(_ context.Context, addrs []netip.Addr) map[netip.Addr]error {
	f.batchDeleted = append(f.batchDeleted, append([]netip.Addr(nil), addrs...))
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

func (f *fakeDynamicDirectBypassDirectProbe) ProbeDirect(_ context.Context, host string, ip netip.Addr, port uint16) error {
	f.calls = append(f.calls, fakeDynamicDirectBypassDirectProbeCall{host: host, ip: ip, port: port})
	return f.err
}

func TestDynamicDirectBypassModeForOptionsIncludesMixedInbound(t *testing.T) {
	tests := []struct {
		name    string
		options option.Options
		want    dynamicDirectBypassStartMode
	}{
		{
			name: "tun keeps system route mode",
			options: option.Options{
				Inbounds: []option.Inbound{
					{Type: constant.TypeMixed},
					{Type: constant.TypeTun},
				},
			},
			want: dynamicDirectBypassModeSystemRoute,
		},
		{
			name: "mixed without tun uses cache only mode",
			options: option.Options{
				Inbounds: []option.Inbound{
					{Type: constant.TypeMixed},
				},
			},
			want: dynamicDirectBypassModeRuleCacheOnly,
		},
		{
			name:    "no supported inbound disables dynamic direct bypass",
			options: option.Options{},
			want:    dynamicDirectBypassModeDisabled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dynamicDirectBypassModeForOptions(tt.options); got != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got)
			}
		})
	}
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
			Download:     512,
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

func TestSelectDynamicDirectBypassCandidatesIgnoresDirectAttemptWithoutResponse(t *testing.T) {
	cfg := dynamicDirectBypassConfig{
		Enabled:          true,
		MaxRoutesPerHost: 4,
	}
	connections := []dynamicDirectBypassConnection{
		{
			Host:         "chatgpt.com",
			Destination:  netip.MustParseAddr("104.18.32.47"),
			Outbound:     "direct §hide§",
			OutboundType: "direct",
			Chain:        []string{"direct §hide§"},
			Upload:       512,
			Download:     0,
		},
		{
			Host:         "chatgpt.com",
			Destination:  netip.MustParseAddr("172.64.155.209"),
			Outbound:     "direct §hide§",
			OutboundType: "direct",
			Chain:        []string{"direct §hide§"},
			Upload:       512,
			Download:     dynamicDirectBypassDirectMinDownload,
		},
	}

	candidates := selectDynamicDirectBypassCandidates(connections, cfg, nil)

	if len(candidates) != 0 {
		t.Fatalf("expected unresponsive direct attempts not to seed dynamic bypass routes, got %#v", candidates)
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

func TestSelectDynamicDirectBypassCandidatesIgnoresHiddifyOwnTraffic(t *testing.T) {
	cfg := dynamicDirectBypassConfig{
		Enabled:          true,
		MaxRoutesPerHost: 4,
	}
	connections := []dynamicDirectBypassConnection{
		{
			Host:         "cp.cloudflare.com",
			Destination:  netip.MustParseAddr("104.18.32.47"),
			Outbound:     "direct §hide§",
			OutboundType: "direct",
			Chain:        []string{"direct §hide§"},
			ProcessName:  "Hiddify.exe",
			ProcessPath:  `D:\github.com\hiddify-app\build\windows\x64\runner\Debug\Hiddify.exe`,
			Download:     512,
		},
	}

	candidates := selectDynamicDirectBypassCandidates(connections, cfg, nil)

	if len(candidates) != 0 {
		t.Fatalf("expected Hiddify's own direct traffic not to seed dynamic bypass routes, got %#v", candidates)
	}
}

func TestSelectDynamicDirectBypassCandidatesSelectsSingleRemoteHandshakeFailure(t *testing.T) {
	cfg := dynamicDirectBypassConfig{
		Enabled:          true,
		MaxRoutesPerHost: 4,
	}
	connections := []dynamicDirectBypassConnection{
		remoteHandshakeFailureConnection("smartservice.console.aliyun.com", "47.89.238.193"),
	}

	candidates := selectDynamicDirectBypassCandidates(connections, cfg, nil)

	if len(candidates) != 1 {
		t.Fatalf("expected one remote failure bypass candidate, got %#v", candidates)
	}
	if candidates[0].Host != "smartservice.console.aliyun.com" {
		t.Fatalf("unexpected candidate host: %s", candidates[0].Host)
	}
	if !containsAddr(candidates[0].IPs, netip.MustParseAddr("47.89.238.193")) {
		t.Fatalf("expected observed Aliyun IP in candidate, got %#v", candidates[0].IPs)
	}
}

func TestSelectDynamicDirectBypassCandidatesIgnoresResponsiveRemoteFailure(t *testing.T) {
	cfg := dynamicDirectBypassConfig{
		Enabled:          true,
		MaxRoutesPerHost: 4,
	}
	responsive := remoteHandshakeFailureConnection("www.aliyun.com", "47.246.23.233")
	responsive.Download = 512
	connections := []dynamicDirectBypassConnection{
		responsive,
	}

	candidates := selectDynamicDirectBypassCandidates(connections, cfg, nil)

	if len(candidates) != 0 {
		t.Fatalf("expected responsive remote failures not to be bypassed, got %#v", candidates)
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

func TestDynamicDirectBypassManagerKeepsRemoteFailureRouteOnlyAfterSuccessfulDirectProbe(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	probe := &fakeDynamicDirectBypassDirectProbe{}
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, nil, nil, cachePath)
	manager.directProbe = probe
	candidate := dynamicDirectBypassCandidate{
		Host:      "smartservice.console.aliyun.com",
		IPs:       []netip.Addr{netip.MustParseAddr("47.89.238.193")},
		Reason:    "remote-failure",
		ProbePort: 443,
	}

	manager.applyCandidates(context.Background(), []dynamicDirectBypassCandidate{candidate}, now)

	if len(routeManager.added) != 1 || routeManager.added[0] != netip.MustParseAddr("47.89.238.193") {
		t.Fatalf("expected route to be added after direct probe succeeds, got %#v", routeManager.added)
	}
	if len(routeManager.deleted) != 0 {
		t.Fatalf("expected successful direct probe to keep route, got deletions %#v", routeManager.deleted)
	}
	if len(probe.calls) != 1 || probe.calls[0].host != "smartservice.console.aliyun.com" || probe.calls[0].port != 443 {
		t.Fatalf("expected remote failure route to be probed before keeping it, got %#v", probe.calls)
	}
	cached := readDynamicDirectBypassCache(t, cachePath)
	if len(cached) != 1 || cached[0].IP != "47.89.238.193" {
		t.Fatalf("expected successful direct probe route to be cached, got %#v", cached)
	}
}

func TestDynamicDirectBypassManagerCachesRemoteFailureRouteInCacheOnlyMode(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	probe := &fakeDynamicDirectBypassDirectProbe{}
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, cacheOnlyDynamicDirectBypassRouteManager{}, nil, nil, cachePath)
	manager.directProbe = probe
	notifications := 0
	manager.onRoutesChanged = func() {
		notifications++
	}
	candidate := dynamicDirectBypassCandidate{
		Host:      "smartservice.console.aliyun.com",
		IPs:       []netip.Addr{netip.MustParseAddr("47.89.238.193")},
		Reason:    "remote-failure",
		ProbePort: 443,
	}

	manager.applyCandidates(context.Background(), []dynamicDirectBypassCandidate{candidate}, now)

	if len(probe.calls) != 1 || probe.calls[0].ip != netip.MustParseAddr("47.89.238.193") {
		t.Fatalf("expected cache-only remote failure route to be probed, got %#v", probe.calls)
	}
	cached := readDynamicDirectBypassCache(t, cachePath)
	if len(cached) != 1 || cached[0].IP != "47.89.238.193" {
		t.Fatalf("expected successful cache-only direct probe route to be cached, got %#v", cached)
	}
	if notifications != 1 {
		t.Fatalf("expected cache-only route to notify route-rule reload once, got %d", notifications)
	}
}

func TestDynamicDirectBypassManagerNotifiesWhenNewRouteCanAffectRoutingRules(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, nil, nil, "")
	manager.directProbe = &fakeDynamicDirectBypassDirectProbe{}
	notifications := 0
	manager.onRoutesChanged = func() {
		notifications++
	}
	candidate := dynamicDirectBypassCandidate{
		Host:      "smartservice.console.aliyun.com",
		IPs:       []netip.Addr{netip.MustParseAddr("47.89.238.193")},
		Reason:    "remote-failure",
		ProbePort: 443,
	}

	manager.applyCandidates(context.Background(), []dynamicDirectBypassCandidate{candidate}, now)
	manager.applyCandidates(context.Background(), []dynamicDirectBypassCandidate{candidate}, now.Add(time.Minute))

	if notifications != 1 {
		t.Fatalf("expected one route-rule reload notification for the new route, got %d", notifications)
	}
}

func TestDynamicDirectBypassManagerNotifiesWhenRouteExpires(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, nil, nil, "")
	manager.routes[netip.MustParseAddr("47.89.238.193")] = dynamicDirectBypassRoute{
		Host:      "smartservice.console.aliyun.com",
		IP:        "47.89.238.193",
		ExpiresAt: now.Add(-time.Minute),
	}
	notifications := 0
	manager.onRoutesChanged = func() {
		notifications++
	}

	manager.cleanupExpired(context.Background(), now)

	if notifications != 1 {
		t.Fatalf("expected one route-rule reload notification for expired route, got %d", notifications)
	}
}

func TestScheduleDynamicDirectBypassRouteReloadDebounces(t *testing.T) {
	previousDelay := dynamicDirectBypassRouteReloadDelay
	previousMaxWait := dynamicDirectBypassRouteReloadMaxWait
	previousReload := dynamicDirectBypassRouteReloadFunc
	dynamicDirectBypassRouteReloadDelay = 10 * time.Millisecond
	dynamicDirectBypassRouteReloadMaxWait = time.Second
	reloaded := make(chan struct{}, 2)
	dynamicDirectBypassRouteReloadFunc = func(context.Context) {
		reloaded <- struct{}{}
	}
	t.Cleanup(func() {
		dynamicDirectBypassRouteReloadMu.Lock()
		if dynamicDirectBypassRouteReloadTimer != nil {
			dynamicDirectBypassRouteReloadTimer.Stop()
			dynamicDirectBypassRouteReloadTimer = nil
		}
		dynamicDirectBypassRouteReloadPendingSince = time.Time{}
		dynamicDirectBypassRouteReloadMu.Unlock()
		dynamicDirectBypassRouteReloadDelay = previousDelay
		dynamicDirectBypassRouteReloadMaxWait = previousMaxWait
		dynamicDirectBypassRouteReloadFunc = previousReload
	})

	scheduleDynamicDirectBypassRouteReload()
	scheduleDynamicDirectBypassRouteReload()

	select {
	case <-reloaded:
	case <-time.After(time.Second):
		t.Fatal("expected debounced dynamic direct bypass route reload")
	}
	select {
	case <-reloaded:
		t.Fatal("expected repeated schedule calls to debounce into one reload")
	case <-time.After(30 * time.Millisecond):
	}
}

func TestScheduleDynamicDirectBypassRouteReloadWaitsForIdleConnections(t *testing.T) {
	previousDelay := dynamicDirectBypassRouteReloadDelay
	previousIdleDelay := dynamicDirectBypassRouteReloadIdleCheckInterval
	previousMaxWait := dynamicDirectBypassRouteReloadMaxWait
	previousReload := dynamicDirectBypassRouteReloadFunc
	previousActiveConnections := dynamicDirectBypassRouteReloadActiveConnections
	dynamicDirectBypassRouteReloadDelay = 10 * time.Millisecond
	dynamicDirectBypassRouteReloadIdleCheckInterval = 10 * time.Millisecond
	dynamicDirectBypassRouteReloadMaxWait = time.Second
	var activeConnections int32 = 1
	reloaded := make(chan struct{}, 1)
	dynamicDirectBypassRouteReloadFunc = func(context.Context) {
		reloaded <- struct{}{}
	}
	dynamicDirectBypassRouteReloadActiveConnections = func() int {
		return int(atomic.LoadInt32(&activeConnections))
	}
	t.Cleanup(func() {
		dynamicDirectBypassRouteReloadMu.Lock()
		if dynamicDirectBypassRouteReloadTimer != nil {
			dynamicDirectBypassRouteReloadTimer.Stop()
			dynamicDirectBypassRouteReloadTimer = nil
		}
		dynamicDirectBypassRouteReloadPendingSince = time.Time{}
		dynamicDirectBypassRouteReloadMu.Unlock()
		dynamicDirectBypassRouteReloadDelay = previousDelay
		dynamicDirectBypassRouteReloadIdleCheckInterval = previousIdleDelay
		dynamicDirectBypassRouteReloadMaxWait = previousMaxWait
		dynamicDirectBypassRouteReloadFunc = previousReload
		dynamicDirectBypassRouteReloadActiveConnections = previousActiveConnections
	})

	scheduleDynamicDirectBypassRouteReload()

	select {
	case <-reloaded:
		t.Fatal("expected route-rule reload to wait while active connections exist")
	case <-time.After(40 * time.Millisecond):
	}

	atomic.StoreInt32(&activeConnections, 0)
	select {
	case <-reloaded:
	case <-time.After(time.Second):
		t.Fatal("expected pending route-rule reload after active connections drain")
	}
}

func TestScheduleDynamicDirectBypassRouteReloadForcesAfterMaxWait(t *testing.T) {
	previousDelay := dynamicDirectBypassRouteReloadDelay
	previousIdleDelay := dynamicDirectBypassRouteReloadIdleCheckInterval
	previousMaxWait := dynamicDirectBypassRouteReloadMaxWait
	previousReload := dynamicDirectBypassRouteReloadFunc
	previousActiveConnections := dynamicDirectBypassRouteReloadActiveConnections
	dynamicDirectBypassRouteReloadDelay = 10 * time.Millisecond
	dynamicDirectBypassRouteReloadIdleCheckInterval = 10 * time.Millisecond
	dynamicDirectBypassRouteReloadMaxWait = 25 * time.Millisecond
	reloaded := make(chan struct{}, 1)
	dynamicDirectBypassRouteReloadFunc = func(context.Context) {
		reloaded <- struct{}{}
	}
	dynamicDirectBypassRouteReloadActiveConnections = func() int {
		return 1
	}
	t.Cleanup(func() {
		dynamicDirectBypassRouteReloadMu.Lock()
		if dynamicDirectBypassRouteReloadTimer != nil {
			dynamicDirectBypassRouteReloadTimer.Stop()
			dynamicDirectBypassRouteReloadTimer = nil
		}
		dynamicDirectBypassRouteReloadPendingSince = time.Time{}
		dynamicDirectBypassRouteReloadMu.Unlock()
		dynamicDirectBypassRouteReloadDelay = previousDelay
		dynamicDirectBypassRouteReloadIdleCheckInterval = previousIdleDelay
		dynamicDirectBypassRouteReloadMaxWait = previousMaxWait
		dynamicDirectBypassRouteReloadFunc = previousReload
		dynamicDirectBypassRouteReloadActiveConnections = previousActiveConnections
	})

	scheduleDynamicDirectBypassRouteReload()

	select {
	case <-reloaded:
	case <-time.After(time.Second):
		t.Fatal("expected route-rule reload to force after max wait")
	}
}

func TestScheduleDynamicDirectBypassRouteReloadUsesBaseContext(t *testing.T) {
	type reloadContextTestKey struct{}

	previousDelay := dynamicDirectBypassRouteReloadDelay
	previousMaxWait := dynamicDirectBypassRouteReloadMaxWait
	previousReload := dynamicDirectBypassRouteReloadFunc
	previousBaseContext := static.BaseContext
	dynamicDirectBypassRouteReloadDelay = 10 * time.Millisecond
	dynamicDirectBypassRouteReloadMaxWait = time.Second
	key := reloadContextTestKey{}
	static.BaseContext = context.WithValue(context.Background(), key, "base-context")
	reloaded := make(chan any, 1)
	dynamicDirectBypassRouteReloadFunc = func(ctx context.Context) {
		reloaded <- ctx.Value(key)
	}
	t.Cleanup(func() {
		dynamicDirectBypassRouteReloadMu.Lock()
		if dynamicDirectBypassRouteReloadTimer != nil {
			dynamicDirectBypassRouteReloadTimer.Stop()
			dynamicDirectBypassRouteReloadTimer = nil
		}
		dynamicDirectBypassRouteReloadPendingSince = time.Time{}
		dynamicDirectBypassRouteReloadMu.Unlock()
		dynamicDirectBypassRouteReloadDelay = previousDelay
		dynamicDirectBypassRouteReloadMaxWait = previousMaxWait
		dynamicDirectBypassRouteReloadFunc = previousReload
		static.BaseContext = previousBaseContext
	})

	scheduleDynamicDirectBypassRouteReload()

	select {
	case value := <-reloaded:
		if value != "base-context" {
			t.Fatalf("expected route reload to use static base context, got %#v", value)
		}
	case <-time.After(time.Second):
		t.Fatal("expected dynamic direct bypass route reload")
	}
}

func TestDynamicDirectBypassManagerDropsRemoteFailureRouteWhenDirectProbeFails(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	probe := &fakeDynamicDirectBypassDirectProbe{err: errors.New("direct tls handshake failed")}
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, nil, nil, cachePath)
	manager.directProbe = probe
	candidate := dynamicDirectBypassCandidate{
		Host:      "chatgpt.com",
		IPs:       []netip.Addr{netip.MustParseAddr("172.64.155.209")},
		Reason:    "remote-failure",
		ProbePort: 443,
	}

	manager.applyCandidates(context.Background(), []dynamicDirectBypassCandidate{candidate}, now)

	if len(routeManager.added) != 1 || routeManager.added[0] != netip.MustParseAddr("172.64.155.209") {
		t.Fatalf("expected temporary route to be added for direct probe, got %#v", routeManager.added)
	}
	if len(routeManager.deleted) != 1 || routeManager.deleted[0] != netip.MustParseAddr("172.64.155.209") {
		t.Fatalf("expected failed direct probe route to be deleted, got %#v", routeManager.deleted)
	}
	if len(manager.routes) != 0 {
		t.Fatalf("expected failed direct probe route not to be kept, got %#v", manager.routes)
	}
	if _, err := os.Stat(cachePath); err == nil {
		cached := readDynamicDirectBypassCache(t, cachePath)
		t.Fatalf("expected failed direct probe route not to be cached, got %#v", cached)
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestDynamicDirectBypassManagerRemovesExistingRouteWhenRemoteFailureProbeFails(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	probe := &fakeDynamicDirectBypassDirectProbe{err: errors.New("direct tls handshake failed")}
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, nil, nil, cachePath)
	manager.directProbe = probe
	ip := netip.MustParseAddr("104.18.32.47")
	manager.routes[ip] = dynamicDirectBypassRoute{
		Host:      "chatgpt.com",
		IP:        ip.String(),
		LastSeen:  now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
	}
	manager.saveCacheLocked()
	candidate := dynamicDirectBypassCandidate{
		Host:      "chatgpt.com",
		IPs:       []netip.Addr{ip},
		Reason:    "remote-failure",
		ProbePort: 443,
	}

	manager.applyCandidates(context.Background(), []dynamicDirectBypassCandidate{candidate}, now)

	if len(probe.calls) != 1 || probe.calls[0].ip != ip {
		t.Fatalf("expected existing remote-failure route to be re-probed, got %#v", probe.calls)
	}
	if len(routeManager.deleted) != 1 || routeManager.deleted[0] != ip {
		t.Fatalf("expected failed existing route to be deleted, got %#v", routeManager.deleted)
	}
	if len(manager.routes) != 0 {
		t.Fatalf("expected failed existing route to be removed from memory, got %#v", manager.routes)
	}
	if cached := readDynamicDirectBypassCache(t, cachePath); len(cached) != 0 {
		t.Fatalf("expected failed existing route to be removed from cache, got %#v", cached)
	}
}

func TestDynamicDirectBypassManagerRemovesExistingRouteAfterFailedDirectAttempt(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, nil, nil, cachePath)
	ip := netip.MustParseAddr("172.64.155.209")
	manager.routes[ip] = dynamicDirectBypassRoute{
		Host:      "chatgpt.com",
		IP:        ip.String(),
		LastSeen:  now.Add(-time.Minute),
		ExpiresAt: now.Add(time.Hour),
	}
	manager.saveCacheLocked()

	manager.cleanupFailedDirectRoutes(context.Background(), []dynamicDirectBypassConnection{
		{
			Host:            "chatgpt.com",
			Destination:     ip,
			DestinationPort: 443,
			Network:         "tcp",
			Outbound:        "direct §hide§",
			OutboundType:    "direct",
			Chain:           []string{"direct §hide§"},
			Upload:          512,
			Download:        0,
			CreatedAt:       now,
			ClosedAt:        now.Add(2 * time.Second),
		},
	})

	if len(routeManager.deleted) != 1 || routeManager.deleted[0] != ip {
		t.Fatalf("expected failed direct route to be deleted, got %#v", routeManager.deleted)
	}
	if len(manager.routes) != 0 {
		t.Fatalf("expected failed direct route to be removed from memory, got %#v", manager.routes)
	}
	if cached := readDynamicDirectBypassCache(t, cachePath); len(cached) != 0 {
		t.Fatalf("expected failed direct route to be removed from cache, got %#v", cached)
	}
}

func TestDynamicDirectBypassManagerBacksOffFailedRemoteProbe(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	probe := &fakeDynamicDirectBypassDirectProbe{err: errors.New("direct tls handshake failed")}
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, nil, nil, cachePath)
	manager.directProbe = probe
	candidate := dynamicDirectBypassCandidate{
		Host:      "mtalk.google.com",
		IPs:       []netip.Addr{netip.MustParseAddr("142.250.99.188")},
		Reason:    "remote-failure",
		ProbePort: 443,
	}

	manager.applyCandidates(context.Background(), []dynamicDirectBypassCandidate{candidate}, now)
	manager.applyCandidates(context.Background(), []dynamicDirectBypassCandidate{candidate}, now.Add(time.Minute))

	if len(probe.calls) != 1 {
		t.Fatalf("expected recent failed direct probe to be skipped, got %#v", probe.calls)
	}
	if len(routeManager.added) != 1 || len(routeManager.deleted) != 1 {
		t.Fatalf("expected one temporary route for failed probe, got added=%#v deleted=%#v", routeManager.added, routeManager.deleted)
	}

	probe.err = nil
	manager.applyCandidates(context.Background(), []dynamicDirectBypassCandidate{candidate}, now.Add(6*time.Minute))

	if len(probe.calls) != 2 {
		t.Fatalf("expected direct probe to retry after backoff, got %#v", probe.calls)
	}
	cached := readDynamicDirectBypassCache(t, cachePath)
	if len(cached) != 1 || cached[0].IP != "142.250.99.188" {
		t.Fatalf("expected successful retry to be cached, got %#v", cached)
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

func TestDynamicDirectBypassManagerClosesRoutesInBatchWhenAvailable(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeBatchDynamicDirectBypassRouteManager{}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, nil, nil, cachePath)
	manager.routes[netip.MustParseAddr("101.226.99.155")] = dynamicDirectBypassRoute{
		Host:      "cube.weixinbridge.com",
		IP:        "101.226.99.155",
		LastSeen:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	manager.routes[netip.MustParseAddr("101.226.99.156")] = dynamicDirectBypassRoute{
		Host:      "cube.weixinbridge.com",
		IP:        "101.226.99.156",
		LastSeen:  now,
		ExpiresAt: now.Add(time.Hour),
	}

	manager.close(context.Background())

	if len(routeManager.deleted) != 0 {
		t.Fatalf("expected batch close not to issue per-route deletes, got %#v", routeManager.deleted)
	}
	if len(routeManager.batchDeleted) != 1 || len(routeManager.batchDeleted[0]) != 2 {
		t.Fatalf("expected close to delete routes in one batch, got %#v", routeManager.batchDeleted)
	}
}

func TestStopActiveDynamicDirectBypassStopsManagerWithoutCacheCleanup(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeBatchDynamicDirectBypassRouteManager{}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, nil, nil, cachePath)
	manager.routes[netip.MustParseAddr("101.226.99.155")] = dynamicDirectBypassRoute{
		Host:      "cube.weixinbridge.com",
		IP:        "101.226.99.155",
		LastSeen:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	canceled := false
	previousManager := static.dynamicDirectBypass
	previousCancel := static.dynamicDirectBypassCancel
	static.dynamicDirectBypass = manager
	static.dynamicDirectBypassCancel = func() { canceled = true }
	t.Cleanup(func() {
		static.dynamicDirectBypass = previousManager
		static.dynamicDirectBypassCancel = previousCancel
	})

	if !stopActiveDynamicDirectBypass(context.Background()) {
		t.Fatal("expected active dynamic direct bypass to be stopped")
	}

	if !canceled {
		t.Fatal("expected active dynamic direct bypass context to be cancelled")
	}
	if static.dynamicDirectBypass != nil || static.dynamicDirectBypassCancel != nil {
		t.Fatal("expected active dynamic direct bypass globals to be cleared")
	}
	if len(routeManager.batchDeleted) != 1 || len(routeManager.batchDeleted[0]) != 1 {
		t.Fatalf("expected active routes to be deleted through manager close only once, got %#v", routeManager.batchDeleted)
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
			Download:     512,
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

func TestDynamicDirectBypassManagerDropsCachedHiddifyOwnRoutesOnLoad(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeDynamicDirectBypassRouteManager{}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	writeDynamicDirectBypassCache(t, cachePath, []dynamicDirectBypassRoute{
		{
			Host:        "cp.cloudflare.com",
			IP:          "104.18.32.47",
			ProcessName: "Hiddify.exe",
			ProcessPath: `D:\github.com\hiddify-app\build\windows\x64\runner\Debug\Hiddify.exe`,
			LastSeen:    now,
			ExpiresAt:   now.Add(30 * time.Minute),
		},
		{
			Host:      "smartservice.console.aliyun.com",
			IP:        "47.89.238.193",
			LastSeen:  now,
			ExpiresAt: now.Add(30 * time.Minute),
		},
	})
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, nil, nil, cachePath)

	if err := manager.loadCacheAndApply(context.Background(), now); err != nil {
		t.Fatal(err)
	}

	if len(routeManager.added) != 1 || routeManager.added[0] != netip.MustParseAddr("47.89.238.193") {
		t.Fatalf("expected only non-Hiddify cached routes to be restored, got %#v", routeManager.added)
	}
	cached := readDynamicDirectBypassCache(t, cachePath)
	if len(cached) != 1 || cached[0].IP != "47.89.238.193" {
		t.Fatalf("expected Hiddify-owned route to be pruned from cache, got %#v", cached)
	}
}

func TestDynamicDirectBypassManagerLoadsCachedRoutesInBatchWhenAvailable(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeBatchDynamicDirectBypassRouteManager{}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	writeDynamicDirectBypassCache(t, cachePath, []dynamicDirectBypassRoute{
		{
			Host:      "auth.huaweicloud.com",
			IP:        "117.78.12.125",
			LastSeen:  now,
			ExpiresAt: now.Add(30 * time.Minute),
		},
		{
			Host:      "auth.huaweicloud.com",
			IP:        "117.78.12.126",
			LastSeen:  now,
			ExpiresAt: now.Add(30 * time.Minute),
		},
	})
	manager := newDynamicDirectBypassManager(dynamicDirectBypassConfig{
		Enabled:          true,
		RouteTTL:         5 * time.Minute,
		MaxRoutes:        10,
		MaxRoutesPerHost: 4,
	}, routeManager, nil, nil, cachePath)

	if err := manager.loadCacheAndApply(context.Background(), now); err != nil {
		t.Fatal(err)
	}

	if len(routeManager.added) != 0 {
		t.Fatalf("expected batch restore not to issue per-route adds, got %#v", routeManager.added)
	}
	if len(routeManager.batchAdded) != 1 || len(routeManager.batchAdded[0]) != 2 {
		t.Fatalf("expected cached routes to be restored in one batch, got %#v", routeManager.batchAdded)
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

func TestCleanupDynamicDirectBypassCachedSystemRoutesUsesBatchWhenAvailable(t *testing.T) {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	routeManager := &fakeBatchDynamicDirectBypassRouteManager{}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	writeDynamicDirectBypassCache(t, cachePath, []dynamicDirectBypassRoute{
		{
			Host:      "auth.huaweicloud.com",
			IP:        "117.78.12.125",
			LastSeen:  now,
			ExpiresAt: now.Add(30 * time.Minute),
		},
		{
			Host:      "auth.huaweicloud.com",
			IP:        "117.78.12.126",
			LastSeen:  now,
			ExpiresAt: now.Add(30 * time.Minute),
		},
	})

	cleanupDynamicDirectBypassCachedSystemRoutes(context.Background(), routeManager, cachePath)

	if len(routeManager.deleted) != 0 {
		t.Fatalf("expected batch cleanup not to issue per-route deletes, got %#v", routeManager.deleted)
	}
	if len(routeManager.batchDeleted) != 1 || len(routeManager.batchDeleted[0]) != 2 {
		t.Fatalf("expected cached system routes to be deleted in one batch, got %#v", routeManager.batchDeleted)
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
			Download:     512,
		},
		{
			Host:         "cube.weixinbridge.com",
			Outbound:     "direct §hide§",
			OutboundType: "direct",
			Chain:        []string{"direct §hide§"},
			Download:     512,
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
		Download:     512,
	}
}

func remoteHandshakeFailureConnection(host string, ip string) dynamicDirectBypassConnection {
	now := time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC)
	return dynamicDirectBypassConnection{
		Host:            host,
		Destination:     netip.MustParseAddr(ip),
		DestinationPort: 443,
		Network:         "tcp",
		Outbound:        "209.87.93.20 tls_h2 grpc direct vless § 443 1",
		OutboundType:    "vless",
		Chain:           []string{"select", "lowest", "209.87.93.20 tls_h2 grpc direct vless § 443 1"},
		Upload:          512,
		Download:        0,
		CreatedAt:       now,
		ClosedAt:        now.Add(2 * time.Second),
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
