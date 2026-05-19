package hcore

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/clashapi/trafficontrol"
	"github.com/sagernet/sing-box/option"
)

const (
	customDynamicDirectBypassEnabledKey       = "hiddify-dynamic-direct-bypass-enabled"
	customDynamicDirectBypassTTLKey           = "hiddify-dynamic-direct-bypass-ttl"
	customDynamicDirectBypassMaxRoutesKey     = "hiddify-dynamic-direct-bypass-max-routes"
	customDynamicDirectBypassMaxRoutesHostKey = "hiddify-dynamic-direct-bypass-max-routes-per-host"
	customDynamicDirectBypassEagerSuffixesKey = "hiddify-dynamic-direct-bypass-eager-domain-suffixes"
)

type dynamicDirectBypassConfig struct {
	Enabled          bool
	SampleInterval   time.Duration
	DNSCacheInterval time.Duration
	RouteTTL         time.Duration
	MaxRoutes        int
	MaxRoutesPerHost int
	ProtectedIPs     map[netip.Addr]struct{}
	EagerSuffixes    []string
}

type dynamicDirectBypassConnection struct {
	Host         string
	Destination  netip.Addr
	Outbound     string
	OutboundType string
	Chain        []string
	ProcessName  string
	ProcessPath  string
	ProcessID    uint32
	UserName     string
	PackageNames []string
}

type dynamicDirectBypassCandidate struct {
	Host    string
	IPs     []netip.Addr
	Process dynamicDirectBypassProcess
}

type dynamicDirectBypassProcess struct {
	ProcessName  string
	ProcessPath  string
	ProcessID    uint32
	UserName     string
	PackageNames []string
}

type dynamicDirectBypassRoute struct {
	Host         string    `json:"host"`
	IP           string    `json:"ip"`
	ProcessName  string    `json:"process_name,omitempty"`
	ProcessPath  string    `json:"process_path,omitempty"`
	ProcessID    uint32    `json:"process_id,omitempty"`
	UserName     string    `json:"user_name,omitempty"`
	PackageNames []string  `json:"package_names,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastSeen     time.Time `json:"last_seen"`
}

type dynamicDirectBypassRouteManager interface {
	AddHostRoute(ctx context.Context, addr netip.Addr) error
	DeleteHostRoute(ctx context.Context, addr netip.Addr) error
}

type dynamicDirectBypassResolver interface {
	LookupNetIP(ctx context.Context, network string, host string) ([]netip.Addr, error)
}

type dynamicDirectBypassDNSCacheReader interface {
	LookupCachedHostIPs(ctx context.Context, suffixes []string) ([]dynamicDirectBypassCandidate, error)
}

type dynamicDirectBypassManager struct {
	config       dynamicDirectBypassConfig
	routeManager dynamicDirectBypassRouteManager
	resolver     dynamicDirectBypassResolver
	dnsCache     dynamicDirectBypassDNSCacheReader
	cachePath    string

	initialRestoreOnce sync.Once
	access             sync.Mutex
	routes             map[netip.Addr]dynamicDirectBypassRoute
}

func defaultDynamicDirectBypassConfig() dynamicDirectBypassConfig {
	return dynamicDirectBypassConfig{
		Enabled:          true,
		SampleInterval:   time.Second,
		DNSCacheInterval: 5 * time.Second,
		RouteTTL:         24 * time.Hour,
		MaxRoutes:        2048,
		MaxRoutesPerHost: 32,
	}
}

func newDynamicDirectBypassManager(
	config dynamicDirectBypassConfig,
	routeManager dynamicDirectBypassRouteManager,
	resolver dynamicDirectBypassResolver,
	dnsCache dynamicDirectBypassDNSCacheReader,
	cachePath string,
) *dynamicDirectBypassManager {
	config = normalizeDynamicDirectBypassConfig(config)
	return &dynamicDirectBypassManager{
		config:       config,
		routeManager: routeManager,
		resolver:     resolver,
		dnsCache:     dnsCache,
		cachePath:    cachePath,
		routes:       map[netip.Addr]dynamicDirectBypassRoute{},
	}
}

func normalizeDynamicDirectBypassConfig(config dynamicDirectBypassConfig) dynamicDirectBypassConfig {
	defaults := defaultDynamicDirectBypassConfig()
	if config.SampleInterval <= 0 {
		config.SampleInterval = defaults.SampleInterval
	}
	if config.DNSCacheInterval <= 0 {
		config.DNSCacheInterval = defaults.DNSCacheInterval
	}
	if config.RouteTTL <= 0 {
		config.RouteTTL = defaults.RouteTTL
	}
	if config.MaxRoutes < 1 {
		config.MaxRoutes = defaults.MaxRoutes
	}
	if config.MaxRoutesPerHost < 1 {
		config.MaxRoutesPerHost = defaults.MaxRoutesPerHost
	}
	config.EagerSuffixes = normalizeDynamicDirectBypassSuffixes(config.EagerSuffixes)
	return config
}

func selectDynamicDirectBypassCandidates(
	connections []dynamicDirectBypassConnection,
	config dynamicDirectBypassConfig,
	protected map[netip.Addr]struct{},
) []dynamicDirectBypassCandidate {
	config = normalizeDynamicDirectBypassConfig(config)
	if !config.Enabled {
		return nil
	}
	type hostState struct {
		count   int
		ips     map[netip.Addr]struct{}
		process dynamicDirectBypassProcess
	}
	hosts := map[string]*hostState{}
	for _, connection := range connections {
		if !isDynamicDirectBypassDirectConnection(connection) {
			continue
		}
		host := normalizeDynamicDirectBypassHost(connection.Host)
		routeableDestination := isDynamicDirectBypassRouteIP(connection.Destination, protected)
		if connection.Destination.IsValid() && !routeableDestination {
			continue
		}
		if host == "" && routeableDestination {
			host = connection.Destination.String()
		}
		if host == "" {
			continue
		}
		state := hosts[host]
		if state == nil {
			state = &hostState{ips: map[netip.Addr]struct{}{}}
			hosts[host] = state
		}
		state.count++
		state.process = mergeDynamicDirectBypassProcess(state.process, dynamicDirectBypassProcessFromConnection(connection))
		if routeableDestination {
			state.ips[connection.Destination] = struct{}{}
		}
	}
	candidates := make([]dynamicDirectBypassCandidate, 0, len(hosts))
	for host, state := range hosts {
		if state.count < 1 {
			continue
		}
		ips := make([]netip.Addr, 0, len(state.ips))
		for ip := range state.ips {
			ips = append(ips, ip)
		}
		sortAddrSlice(ips)
		if len(ips) > config.MaxRoutesPerHost {
			ips = ips[:config.MaxRoutesPerHost]
		}
		candidates = append(candidates, dynamicDirectBypassCandidate{Host: host, IPs: ips, Process: state.process})
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Host < candidates[j].Host
	})
	return candidates
}

func (m *dynamicDirectBypassManager) applyCandidates(
	ctx context.Context,
	candidates []dynamicDirectBypassCandidate,
	now time.Time,
) {
	if m == nil || m.routeManager == nil {
		return
	}
	m.access.Lock()
	defer m.access.Unlock()
	changed := false
	defer func() {
		if changed {
			m.saveCacheLocked()
		}
	}()
	for _, candidate := range candidates {
		for _, ip := range m.expandCandidateIPs(ctx, candidate) {
			if route, exists := m.routes[ip]; exists {
				route.Host = candidate.Host
				route.LastSeen = now
				route.ExpiresAt = now.Add(m.config.RouteTTL)
				updateDynamicDirectBypassRouteProcess(&route, candidate.Process)
				m.routes[ip] = route
				changed = true
				continue
			}
			if len(m.routes) >= m.config.MaxRoutes {
				return
			}
			if err := m.routeManager.AddHostRoute(ctx, ip); err != nil {
				Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass add route failed: ", ip, " ", err)
				continue
			}
			m.routes[ip] = dynamicDirectBypassRoute{
				Host:      candidate.Host,
				IP:        ip.String(),
				LastSeen:  now,
				ExpiresAt: now.Add(m.config.RouteTTL),
			}
			route := m.routes[ip]
			updateDynamicDirectBypassRouteProcess(&route, candidate.Process)
			m.routes[ip] = route
			changed = true
			Log(LogLevel_INFO, LogType_CORE, "dynamic direct bypass route added: ", candidate.Host, " -> ", ip)
		}
	}
}

func (m *dynamicDirectBypassManager) cleanupExpired(ctx context.Context, now time.Time) {
	if m == nil || m.routeManager == nil {
		return
	}
	m.access.Lock()
	defer m.access.Unlock()
	changed := false
	for ip, route := range m.routes {
		if now.Before(route.ExpiresAt) {
			continue
		}
		if err := m.routeManager.DeleteHostRoute(ctx, ip); err != nil {
			Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass delete expired route failed: ", ip, " ", err)
		}
		delete(m.routes, ip)
		changed = true
		Log(LogLevel_INFO, LogType_CORE, "dynamic direct bypass route expired: ", route.Host, " -> ", ip)
	}
	if changed {
		m.saveCacheLocked()
	}
}

func (m *dynamicDirectBypassManager) close(ctx context.Context) {
	if m == nil || m.routeManager == nil {
		return
	}
	m.access.Lock()
	defer m.access.Unlock()
	m.saveCacheLocked()
	for ip := range m.routes {
		if err := m.routeManager.DeleteHostRoute(ctx, ip); err != nil {
			Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass delete route failed: ", ip, " ", err)
		}
		delete(m.routes, ip)
	}
}

func (m *dynamicDirectBypassManager) run(ctx context.Context, snapshot func() []dynamicDirectBypassConnection) {
	if m == nil || !m.config.Enabled || snapshot == nil {
		return
	}
	m.restoreInitial(ctx, time.Now())
	connectionTicker := time.NewTicker(m.config.SampleInterval)
	defer connectionTicker.Stop()
	dnsCacheTicker := time.NewTicker(m.config.DNSCacheInterval)
	defer dnsCacheTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-connectionTicker.C:
			m.cleanupExpired(ctx, now)
			candidates := selectDynamicDirectBypassCandidates(snapshot(), m.config, m.config.ProtectedIPs)
			if len(candidates) > 0 {
				m.applyCandidates(ctx, candidates, now)
			}
		case now := <-dnsCacheTicker.C:
			m.applyDNSCacheCandidates(ctx, now)
		}
	}
}

func (m *dynamicDirectBypassManager) restoreInitial(ctx context.Context, now time.Time) {
	if m == nil || !m.config.Enabled {
		return
	}
	m.initialRestoreOnce.Do(func() {
		if err := m.loadCacheAndApply(ctx, now); err != nil {
			Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass cache restore failed: ", err)
		}
		m.applyDNSCacheCandidates(ctx, now)
	})
}

func (m *dynamicDirectBypassManager) applyDNSCacheCandidates(ctx context.Context, now time.Time) {
	if m == nil || m.dnsCache == nil || len(m.config.EagerSuffixes) == 0 {
		return
	}
	candidates, err := m.dnsCache.LookupCachedHostIPs(ctx, m.config.EagerSuffixes)
	if err != nil {
		Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass dns cache lookup failed: ", err)
		return
	}
	if len(candidates) == 0 {
		return
	}
	m.applyCandidates(ctx, candidates, now)
}

func (m *dynamicDirectBypassManager) expandCandidateIPs(
	ctx context.Context,
	candidate dynamicDirectBypassCandidate,
) []netip.Addr {
	seen := map[netip.Addr]struct{}{}
	ips := make([]netip.Addr, 0, len(candidate.IPs))
	addIP := func(ip netip.Addr) {
		if !isDynamicDirectBypassRouteIP(ip, m.config.ProtectedIPs) {
			return
		}
		if _, exists := seen[ip]; exists {
			return
		}
		seen[ip] = struct{}{}
		ips = append(ips, ip)
	}
	for _, ip := range candidate.IPs {
		addIP(ip)
	}
	shouldResolve := len(ips) == 0 || matchesDynamicDirectBypassSuffix(candidate.Host, m.config.EagerSuffixes)
	if m.resolver != nil && shouldResolve && len(ips) < m.config.MaxRoutesPerHost {
		if resolved, err := m.resolver.LookupNetIP(ctx, "ip4", candidate.Host); err == nil {
			for _, ip := range resolved {
				addIP(ip)
				if len(ips) >= m.config.MaxRoutesPerHost {
					break
				}
			}
		}
	}
	sortAddrSlice(ips)
	if len(ips) > m.config.MaxRoutesPerHost {
		return ips[:m.config.MaxRoutesPerHost]
	}
	return ips
}

func (m *dynamicDirectBypassManager) loadCacheAndApply(ctx context.Context, now time.Time) error {
	if m == nil || m.cachePath == "" || m.routeManager == nil {
		return nil
	}
	data, err := os.ReadFile(m.cachePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var cached []dynamicDirectBypassRoute
	if err := json.Unmarshal(data, &cached); err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	changed := false
	for _, route := range cached {
		ip, err := netip.ParseAddr(route.IP)
		if err != nil || !isDynamicDirectBypassRouteIP(ip, m.config.ProtectedIPs) {
			changed = true
			continue
		}
		if !now.Before(route.ExpiresAt) {
			if err := m.routeManager.DeleteHostRoute(ctx, ip); err != nil {
				Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass delete expired cached route failed: ", ip, " ", err)
			}
			changed = true
			continue
		}
		if len(m.routes) >= m.config.MaxRoutes {
			changed = true
			break
		}
		if err := m.routeManager.AddHostRoute(ctx, ip); err != nil {
			Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass restore route failed: ", ip, " ", err)
			changed = true
			continue
		}
		m.routes[ip] = route
	}
	if changed {
		m.saveCacheLocked()
	}
	return nil
}

func cleanupDynamicDirectBypassCachedSystemRoutes(
	ctx context.Context,
	routeManager dynamicDirectBypassRouteManager,
	cachePath string,
) {
	if routeManager == nil || cachePath == "" {
		return
	}
	data, err := os.ReadFile(cachePath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass cache cleanup read failed: ", err)
		}
		return
	}
	var cached []dynamicDirectBypassRoute
	if err := json.Unmarshal(data, &cached); err != nil {
		Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass cache cleanup parse failed: ", err)
		return
	}
	for _, route := range cached {
		ip, err := netip.ParseAddr(route.IP)
		if err != nil {
			continue
		}
		if err := routeManager.DeleteHostRoute(ctx, ip); err != nil {
			Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass delete cached route failed: ", ip, " ", err)
			continue
		}
		Log(LogLevel_INFO, LogType_CORE, "dynamic direct bypass cached route deleted: ", route.Host, " -> ", ip)
	}
}

func (m *dynamicDirectBypassManager) saveCacheLocked() {
	if m == nil || m.cachePath == "" {
		return
	}
	routes := make([]dynamicDirectBypassRoute, 0, len(m.routes))
	for _, route := range m.routes {
		routes = append(routes, route)
	}
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].IP < routes[j].IP
	})
	if err := os.MkdirAll(filepath.Dir(m.cachePath), 0o755); err != nil {
		Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass cache mkdir failed: ", err)
		return
	}
	data, err := json.MarshalIndent(routes, "", "  ")
	if err != nil {
		Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass cache marshal failed: ", err)
		return
	}
	if err := os.WriteFile(m.cachePath, data, 0o644); err != nil {
		Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass cache write failed: ", err)
	}
}

func dynamicDirectBypassConnectionsFromTrackers(trackers []*trafficontrol.TrackerMetadata) []dynamicDirectBypassConnection {
	connections := make([]dynamicDirectBypassConnection, 0, len(trackers))
	for _, tracker := range trackers {
		if tracker == nil {
			continue
		}
		host := tracker.Metadata.Domain
		if host == "" {
			host = tracker.Metadata.Destination.Fqdn
		}
		connections = append(connections, dynamicDirectBypassConnection{
			Host:         host,
			Destination:  tracker.Metadata.Destination.Addr,
			Outbound:     tracker.Outbound,
			OutboundType: tracker.OutboundType,
			Chain:        tracker.Chain,
			ProcessName:  processNameFromTracker(tracker),
			ProcessPath:  processPathFromTracker(tracker),
			ProcessID:    processIDFromTracker(tracker),
			UserName:     userNameFromTracker(tracker),
			PackageNames: packageNamesFromTracker(tracker),
		})
	}
	return connections
}

func dynamicDirectBypassProcessFromConnection(connection dynamicDirectBypassConnection) dynamicDirectBypassProcess {
	processName := strings.TrimSpace(connection.ProcessName)
	processPath := strings.TrimSpace(connection.ProcessPath)
	if processName == "" {
		processName = processNameFromPath(processPath)
	}
	return dynamicDirectBypassProcess{
		ProcessName:  processName,
		ProcessPath:  processPath,
		ProcessID:    connection.ProcessID,
		UserName:     strings.TrimSpace(connection.UserName),
		PackageNames: uniqueNonEmptyStrings(connection.PackageNames),
	}
}

func mergeDynamicDirectBypassProcess(current dynamicDirectBypassProcess, next dynamicDirectBypassProcess) dynamicDirectBypassProcess {
	if current.ProcessName == "" {
		current.ProcessName = next.ProcessName
	}
	if current.ProcessPath == "" {
		current.ProcessPath = next.ProcessPath
	}
	if current.ProcessID == 0 {
		current.ProcessID = next.ProcessID
	}
	if current.UserName == "" {
		current.UserName = next.UserName
	}
	if len(current.PackageNames) == 0 {
		current.PackageNames = append([]string(nil), next.PackageNames...)
	}
	return current
}

func updateDynamicDirectBypassRouteProcess(route *dynamicDirectBypassRoute, process dynamicDirectBypassProcess) {
	if route == nil {
		return
	}
	if process.ProcessName != "" {
		route.ProcessName = process.ProcessName
	}
	if process.ProcessPath != "" {
		route.ProcessPath = process.ProcessPath
	}
	if process.ProcessID != 0 {
		route.ProcessID = process.ProcessID
	}
	if process.UserName != "" {
		route.UserName = process.UserName
	}
	if len(process.PackageNames) > 0 {
		route.PackageNames = append([]string(nil), process.PackageNames...)
	}
}

func processNameFromTracker(tracker *trafficontrol.TrackerMetadata) string {
	if processName := processNameFromPath(processPathFromTracker(tracker)); processName != "" {
		return processName
	}
	packages := packageNamesFromTracker(tracker)
	if len(packages) > 0 {
		return packages[0]
	}
	return ""
}

func processPathFromTracker(tracker *trafficontrol.TrackerMetadata) string {
	if tracker == nil || tracker.Metadata.ProcessInfo == nil {
		return ""
	}
	return strings.TrimSpace(tracker.Metadata.ProcessInfo.ProcessPath)
}

func processIDFromTracker(tracker *trafficontrol.TrackerMetadata) uint32 {
	if tracker == nil || tracker.Metadata.ProcessInfo == nil {
		return 0
	}
	return tracker.Metadata.ProcessInfo.ProcessID
}

func userNameFromTracker(tracker *trafficontrol.TrackerMetadata) string {
	if tracker == nil || tracker.Metadata.ProcessInfo == nil {
		return ""
	}
	return strings.TrimSpace(tracker.Metadata.ProcessInfo.UserName)
}

func packageNamesFromTracker(tracker *trafficontrol.TrackerMetadata) []string {
	if tracker == nil || tracker.Metadata.ProcessInfo == nil {
		return nil
	}
	return uniqueNonEmptyStrings(tracker.Metadata.ProcessInfo.AndroidPackageNames)
}

func processNameFromPath(processPath string) string {
	processPath = strings.TrimSpace(processPath)
	if processPath == "" {
		return ""
	}
	index := strings.LastIndexAny(processPath, `\/`)
	if index >= 0 && index+1 < len(processPath) {
		return processPath[index+1:]
	}
	return processPath
}

func uniqueNonEmptyStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func dynamicDirectBypassConfigFromOptions(options option.Options) dynamicDirectBypassConfig {
	config := defaultDynamicDirectBypassConfig()
	if options.Custom == nil {
		return config
	}
	custom := *options.Custom
	config.Enabled = boolFromCustom(custom[customDynamicDirectBypassEnabledKey], config.Enabled)
	config.RouteTTL = time.Duration(routeConnectionLimitFromCustom(custom[customDynamicDirectBypassTTLKey], int(config.RouteTTL/time.Second))) * time.Second
	config.MaxRoutes = routeConnectionLimitFromCustom(custom[customDynamicDirectBypassMaxRoutesKey], config.MaxRoutes)
	config.MaxRoutesPerHost = routeConnectionLimitFromCustom(custom[customDynamicDirectBypassMaxRoutesHostKey], config.MaxRoutesPerHost)
	config.EagerSuffixes = stringSliceFromCustom(custom[customDynamicDirectBypassEagerSuffixesKey])
	config.ProtectedIPs = protectedIPsFromOptions(options)
	return normalizeDynamicDirectBypassConfig(config)
}

func protectedIPsFromOptions(options option.Options) map[netip.Addr]struct{} {
	protected := map[netip.Addr]struct{}{}
	addServer := func(server string) {
		host := strings.TrimSpace(server)
		if host == "" {
			return
		}
		if strings.Contains(host, "://") {
			parsedURL, err := url.Parse(host)
			if err != nil {
				return
			}
			host = parsedURL.Hostname()
		} else if splitHost, _, err := net.SplitHostPort(host); err == nil {
			host = splitHost
		}
		host = strings.Trim(host, "[]")
		if addr, err := netip.ParseAddr(host); err == nil {
			protected[addr] = struct{}{}
		}
	}
	for _, outbound := range options.Outbounds {
		if server, ok := outbound.Options.(option.ServerOptionsWrapper); ok {
			addServer(server.TakeServerOptions().Server)
		}
	}
	for _, inbound := range options.Inbounds {
		if tunOptions, ok := inbound.Options.(*option.TunInboundOptions); ok {
			for _, prefix := range tunOptions.RouteExcludeAddress {
				protected[prefix.Addr()] = struct{}{}
			}
		}
	}
	return protected
}

func boolFromCustom(value any, fallback bool) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return fallback
}

func stringSliceFromCustom(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				values = append(values, text)
			}
		}
		return values
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return strings.Split(typed, ",")
	default:
		return nil
	}
}

func isDynamicDirectBypassDirectConnection(connection dynamicDirectBypassConnection) bool {
	if strings.EqualFold(strings.TrimSpace(connection.OutboundType), constant.TypeDirect) {
		return true
	}
	if isDynamicDirectBypassDirectTag(connection.Outbound) {
		return true
	}
	for _, chain := range connection.Chain {
		if isDynamicDirectBypassDirectTag(chain) {
			return true
		}
	}
	return false
}

func isDynamicDirectBypassDirectTag(tag string) bool {
	tag = strings.ToLower(strings.TrimSpace(tag))
	return tag == constant.TypeDirect || tag == "direct §hide§"
}

func normalizeDynamicDirectBypassHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

func normalizeDynamicDirectBypassSuffixes(values []string) []string {
	seen := map[string]struct{}{}
	suffixes := make([]string, 0, len(values))
	for _, value := range values {
		suffix := normalizeDynamicDirectBypassHost(strings.TrimPrefix(strings.TrimSpace(value), "*."))
		if suffix == "" || !strings.Contains(strings.TrimPrefix(suffix, "."), ".") {
			continue
		}
		if _, exists := seen[suffix]; exists {
			continue
		}
		seen[suffix] = struct{}{}
		suffixes = append(suffixes, suffix)
	}
	sort.Strings(suffixes)
	return suffixes
}

func matchesDynamicDirectBypassSuffix(host string, suffixes []string) bool {
	host = normalizeDynamicDirectBypassHost(host)
	for _, suffix := range suffixes {
		trimmed := strings.TrimPrefix(suffix, ".")
		if host == trimmed || strings.HasSuffix(host, "."+trimmed) {
			return true
		}
	}
	return false
}

func isDynamicDirectBypassRouteIP(addr netip.Addr, protected map[netip.Addr]struct{}) bool {
	if !addr.IsValid() || !addr.Is4() {
		return false
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
		return false
	}
	if _, exists := protected[addr]; exists {
		return false
	}
	return true
}

func sortAddrSlice(values []netip.Addr) {
	sort.Slice(values, func(i, j int) bool {
		return values[i].Compare(values[j]) < 0
	})
}

func sortDynamicDirectBypassCandidates(values []dynamicDirectBypassCandidate) {
	sort.Slice(values, func(i, j int) bool {
		return values[i].Host < values[j].Host
	})
}
