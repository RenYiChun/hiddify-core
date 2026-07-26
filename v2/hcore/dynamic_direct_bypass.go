package hcore

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	hconfig "github.com/hiddify/hiddify-core/v2/config"
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

	dynamicDirectBypassRemoteFailureThreshold          = 1
	dynamicDirectBypassRemoteFailureMaxDownload        = 64
	dynamicDirectBypassDirectMinDownload               = 64
	dynamicDirectBypassRemoteFailureMaxDuration        = 30 * time.Second
	dynamicDirectBypassRemoteFailureProbeTimeout       = 3 * time.Second
	dynamicDirectBypassRemoteFailureProbeRetryInterval = 5 * time.Minute
	dynamicDirectBypassRouteSwitchIdleDelay            = 5 * time.Second
	dynamicDirectBypassDirectSuccessMaxAge             = 30 * time.Second

	dynamicDirectBypassReasonDirect        = "direct"
	dynamicDirectBypassReasonRemoteFailure = "remote-failure"
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
	ID              string
	Host            string
	Destination     netip.Addr
	DestinationPort uint16
	Network         string
	Outbound        string
	OutboundType    string
	Chain           []string
	Upload          int64
	Download        int64
	CreatedAt       time.Time
	ClosedAt        time.Time
	ProcessName     string
	ProcessPath     string
	ProcessID       uint32
	UserName        string
	PackageNames    []string
}

type dynamicDirectBypassCandidate struct {
	Host      string
	IPs       []netip.Addr
	Process   dynamicDirectBypassProcess
	Reason    string
	ProbePort uint16
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
	Reason       string    `json:"reason,omitempty"`
	ProcessName  string    `json:"process_name,omitempty"`
	ProcessPath  string    `json:"process_path,omitempty"`
	ProcessID    uint32    `json:"process_id,omitempty"`
	UserName     string    `json:"user_name,omitempty"`
	PackageNames []string  `json:"package_names,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastSeen     time.Time `json:"last_seen"`
}

type dynamicDirectBypassRemoteProbeKey struct {
	host string
	ip   netip.Addr
	port uint16
}

type dynamicDirectBypassPendingRoute struct {
	Candidate dynamicDirectBypassCandidate
	ExpiresAt time.Time
}

type dynamicDirectBypassPendingRouteDelete struct {
	Host     string
	Upload   int64
	Download int64
}

func dynamicDirectBypassRemoteProbeFailureLogLevel(routeRemoved bool) LogLevel {
	if routeRemoved {
		return LogLevel_INFO
	}
	return LogLevel_DEBUG
}

func dynamicDirectBypassOptionalLookupFailureLogLevel() LogLevel {
	return LogLevel_DEBUG
}

type dynamicDirectBypassRouteManager interface {
	AddHostRoute(ctx context.Context, addr netip.Addr) error
	DeleteHostRoute(ctx context.Context, addr netip.Addr) error
}

type dynamicDirectBypassBatchRouteManager interface {
	AddHostRoutes(ctx context.Context, addrs []netip.Addr) map[netip.Addr]error
	DeleteHostRoutes(ctx context.Context, addrs []netip.Addr) map[netip.Addr]error
}

type cacheOnlyDynamicDirectBypassRouteManager struct{}

func (cacheOnlyDynamicDirectBypassRouteManager) AddHostRoute(_ context.Context, _ netip.Addr) error {
	return nil
}

func (cacheOnlyDynamicDirectBypassRouteManager) DeleteHostRoute(_ context.Context, _ netip.Addr) error {
	return nil
}

func (cacheOnlyDynamicDirectBypassRouteManager) AddHostRoutes(_ context.Context, _ []netip.Addr) map[netip.Addr]error {
	return nil
}

func (cacheOnlyDynamicDirectBypassRouteManager) DeleteHostRoutes(_ context.Context, _ []netip.Addr) map[netip.Addr]error {
	return nil
}

type dynamicDirectBypassResolver interface {
	LookupNetIP(ctx context.Context, network string, host string) ([]netip.Addr, error)
}

type dynamicDirectBypassDNSCacheReader interface {
	LookupCachedHostIPs(ctx context.Context, suffixes []string) ([]dynamicDirectBypassCandidate, error)
}

type dynamicDirectBypassDirectProbe interface {
	ProbeDirect(ctx context.Context, host string, ip netip.Addr, port uint16) error
}

type dynamicDirectBypassManager struct {
	config          dynamicDirectBypassConfig
	routeManager    dynamicDirectBypassRouteManager
	resolver        dynamicDirectBypassResolver
	dnsCache        dynamicDirectBypassDNSCacheReader
	directProbe     dynamicDirectBypassDirectProbe
	onRoutesChanged func()
	cachePath       string

	initialRestoreOnce  sync.Once
	access              sync.Mutex
	routes              map[netip.Addr]dynamicDirectBypassRoute
	failedRemoteProbes  map[dynamicDirectBypassRemoteProbeKey]time.Time
	failedDirectRoutes  map[dynamicDirectBypassRemoteProbeKey]time.Time
	activeDestinations  map[netip.Addr]struct{}
	lastActiveAt        map[netip.Addr]time.Time
	pendingRoutes       map[netip.Addr]dynamicDirectBypassPendingRoute
	pendingRouteDeletes map[netip.Addr]dynamicDirectBypassPendingRouteDelete
}

func defaultDynamicDirectBypassConfig() dynamicDirectBypassConfig {
	return dynamicDirectBypassConfig{
		Enabled:          true,
		SampleInterval:   time.Second,
		DNSCacheInterval: 5 * time.Second,
		RouteTTL:         24 * time.Hour,
		MaxRoutes:        256,
		MaxRoutesPerHost: 8,
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
		config:              config,
		routeManager:        routeManager,
		resolver:            resolver,
		dnsCache:            dnsCache,
		directProbe:         defaultDynamicDirectBypassDirectProbe{},
		cachePath:           cachePath,
		routes:              map[netip.Addr]dynamicDirectBypassRoute{},
		failedRemoteProbes:  map[dynamicDirectBypassRemoteProbeKey]time.Time{},
		failedDirectRoutes:  map[dynamicDirectBypassRemoteProbeKey]time.Time{},
		activeDestinations:  map[netip.Addr]struct{}{},
		lastActiveAt:        map[netip.Addr]time.Time{},
		pendingRoutes:       map[netip.Addr]dynamicDirectBypassPendingRoute{},
		pendingRouteDeletes: map[netip.Addr]dynamicDirectBypassPendingRouteDelete{},
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
	return selectDynamicDirectBypassCandidatesAt(connections, config, protected, time.Now())
}

func selectDynamicDirectBypassCandidatesAt(
	connections []dynamicDirectBypassConnection,
	config dynamicDirectBypassConfig,
	protected map[netip.Addr]struct{},
	now time.Time,
) []dynamicDirectBypassCandidate {
	config = normalizeDynamicDirectBypassConfig(config)
	if !config.Enabled {
		return nil
	}
	type hostState struct {
		directCount        int
		remoteFailureCount int
		remoteFailurePort  uint16
		ips                map[netip.Addr]struct{}
		process            dynamicDirectBypassProcess
	}
	hosts := map[string]*hostState{}
	for _, connection := range connections {
		isDirect := isDynamicDirectBypassUsableDirectConnectionAt(connection, now)
		isRemoteFailure := !isDirect && isDynamicDirectBypassRemoteFailureConnection(connection)
		if !isDirect && !isRemoteFailure {
			continue
		}
		process := dynamicDirectBypassProcessFromConnection(connection)
		if isDynamicDirectBypassSelfProcess(process) {
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
		if hconfig.IsDynamicDirectBypassExcludedHost(host) {
			continue
		}
		state := hosts[host]
		if state == nil {
			state = &hostState{ips: map[netip.Addr]struct{}{}}
			hosts[host] = state
		}
		if isRemoteFailure {
			state.remoteFailureCount++
			if state.remoteFailurePort == 0 ||
				state.remoteFailurePort == 80 && connection.DestinationPort == 443 {
				state.remoteFailurePort = connection.DestinationPort
			}
		} else {
			state.directCount++
		}
		state.process = mergeDynamicDirectBypassProcess(state.process, process)
		if routeableDestination {
			state.ips[connection.Destination] = struct{}{}
		}
	}
	candidates := make([]dynamicDirectBypassCandidate, 0, len(hosts))
	for host, state := range hosts {
		reason := dynamicDirectBypassReasonDirect
		if state.directCount < 1 {
			if state.remoteFailureCount < dynamicDirectBypassRemoteFailureThreshold ||
				!isDynamicDirectBypassRemoteFailureAllowed(host, config) {
				continue
			}
			reason = dynamicDirectBypassReasonRemoteFailure
			if state.remoteFailurePort == 0 {
				state.remoteFailurePort = 443
			}
		}
		if state.directCount < 1 && state.remoteFailureCount < 1 {
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
		candidates = append(candidates, dynamicDirectBypassCandidate{
			Host:      host,
			IPs:       ips,
			Process:   state.process,
			Reason:    reason,
			ProbePort: state.remoteFailurePort,
		})
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Host < candidates[j].Host
	})
	return candidates
}

func (m *dynamicDirectBypassManager) updateActiveDestinations(
	connections []dynamicDirectBypassConnection,
	now time.Time,
) {
	if m == nil {
		return
	}
	active := map[netip.Addr]struct{}{}
	for _, connection := range connections {
		if !connection.ClosedAt.IsZero() || !connection.Destination.IsValid() {
			continue
		}
		active[connection.Destination] = struct{}{}
	}

	m.access.Lock()
	defer m.access.Unlock()
	m.activeDestinations = active
	for ip := range active {
		m.lastActiveAt[ip] = now
	}
	for ip, lastActiveAt := range m.lastActiveAt {
		if _, isActive := active[ip]; isActive || now.Sub(lastActiveAt) < dynamicDirectBypassRouteSwitchIdleDelay {
			continue
		}
		if _, hasRoute := m.routes[ip]; hasRoute {
			continue
		}
		if _, isPending := m.pendingRoutes[ip]; isPending {
			continue
		}
		delete(m.lastActiveAt, ip)
	}
}

func (m *dynamicDirectBypassManager) routeSwitchAllowedLocked(ip netip.Addr, now time.Time) bool {
	if _, active := m.activeDestinations[ip]; active {
		return false
	}
	lastActiveAt, wasActive := m.lastActiveAt[ip]
	return !wasActive || now.Sub(lastActiveAt) >= dynamicDirectBypassRouteSwitchIdleDelay
}

func (m *dynamicDirectBypassManager) queuePendingRouteLocked(
	candidate dynamicDirectBypassCandidate,
	ip netip.Addr,
	now time.Time,
) {
	candidate.IPs = []netip.Addr{ip}
	m.pendingRoutes[ip] = dynamicDirectBypassPendingRoute{
		Candidate: candidate,
		ExpiresAt: now.Add(m.config.RouteTTL),
	}
}

func (m *dynamicDirectBypassManager) applyPendingRoutes(ctx context.Context, now time.Time) {
	if m == nil {
		return
	}
	m.access.Lock()
	candidates := make([]dynamicDirectBypassCandidate, 0, len(m.pendingRoutes))
	for ip, pending := range m.pendingRoutes {
		if !now.Before(pending.ExpiresAt) {
			delete(m.pendingRoutes, ip)
			continue
		}
		if !m.routeSwitchAllowedLocked(ip, now) {
			continue
		}
		candidates = append(candidates, pending.Candidate)
		delete(m.pendingRoutes, ip)
	}
	m.access.Unlock()
	if len(candidates) == 0 {
		return
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Host != candidates[j].Host {
			return candidates[i].Host < candidates[j].Host
		}
		return candidates[i].IPs[0].Less(candidates[j].IPs[0])
	})
	m.applyCandidates(ctx, candidates, now)
}

func (m *dynamicDirectBypassManager) applyPendingRouteDeletes(ctx context.Context, now time.Time) {
	if m == nil || m.routeManager == nil {
		return
	}
	m.access.Lock()
	changed := false
	defer func() {
		if changed {
			m.saveCacheLocked()
		}
		m.access.Unlock()
		if changed {
			m.notifyRoutesChanged()
		}
	}()
	for ip, pending := range m.pendingRouteDeletes {
		if _, exists := m.routes[ip]; !exists {
			delete(m.pendingRouteDeletes, ip)
			continue
		}
		if !m.routeSwitchAllowedLocked(ip, now) {
			continue
		}
		if err := m.routeManager.DeleteHostRoute(ctx, ip); err != nil {
			Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass delete deferred failed direct route failed: ", ip, " ", err)
		}
		delete(m.routes, ip)
		delete(m.pendingRouteDeletes, ip)
		changed = true
		Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass deferred failed direct route removed: ",
			pending.Host, " -> ", ip, " upload=", pending.Upload, " download=", pending.Download)
	}
}

func (m *dynamicDirectBypassManager) applyCandidates(
	ctx context.Context,
	candidates []dynamicDirectBypassCandidate,
	now time.Time,
) {
	if m == nil || m.routeManager == nil {
		return
	}
	changed := false
	routeRulesChanged := false
	m.access.Lock()
	defer func() {
		if changed {
			m.saveCacheLocked()
		}
		m.access.Unlock()
		if routeRulesChanged {
			m.notifyRoutesChanged()
		}
	}()
	for _, candidate := range candidates {
		if hconfig.IsDynamicDirectBypassExcludedHost(candidate.Host) {
			continue
		}
		candidateReason := normalizeDynamicDirectBypassReason(candidate.Reason)
		if candidateReason == dynamicDirectBypassReasonRemoteFailure &&
			!isDynamicDirectBypassRemoteFailureAllowed(candidate.Host, m.config) {
			continue
		}
		candidate.Reason = candidateReason
		for _, ip := range m.expandCandidateIPs(ctx, candidate) {
			if route, exists := m.routes[ip]; exists {
				delete(m.pendingRoutes, ip)
				if _, pendingDelete := m.pendingRouteDeletes[ip]; pendingDelete {
					continue
				}
				if candidateReason == dynamicDirectBypassReasonRemoteFailure {
					if !m.routeSwitchAllowedLocked(ip, now) {
						continue
					}
					if m.shouldSkipRemoteFailureProbeLocked(candidate, ip, now) {
						if err := m.routeManager.DeleteHostRoute(ctx, ip); err != nil {
							Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass delete stale remote fallback route failed: ", ip, " ", err)
						}
						delete(m.routes, ip)
						changed = true
						routeRulesChanged = true
						Log(LogLevel_INFO, LogType_CORE, "dynamic direct bypass stale remote fallback route removed after failed probe: ", route.Host, " -> ", ip)
						continue
					}
					if err := m.probeRemoteFailureDirectRoute(ctx, candidate, ip); err != nil {
						if deleteErr := m.routeManager.DeleteHostRoute(ctx, ip); deleteErr != nil {
							Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass delete failed remote fallback route failed: ", ip, " ", deleteErr)
						}
						delete(m.routes, ip)
						changed = true
						routeRulesChanged = true
						m.markRemoteFailureProbeFailedLocked(candidate, ip, now)
						Log(dynamicDirectBypassRemoteProbeFailureLogLevel(true), LogType_CORE, "dynamic direct bypass remote fallback direct probe failed, route removed: ", candidate.Host, " -> ", ip, " ", err)
						continue
					}
					m.clearRemoteFailureProbeFailedLocked(candidate, ip)
				}
				route.Host = candidate.Host
				route.Reason = candidateReason
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
			if candidateReason == dynamicDirectBypassReasonRemoteFailure && m.shouldSkipRemoteFailureProbeLocked(candidate, ip, now) {
				continue
			}
			if candidateReason == dynamicDirectBypassReasonDirect && m.shouldSkipFailedDirectRouteLocked(candidate.Host, ip, candidate.ProbePort, now) {
				continue
			}
			if !m.routeSwitchAllowedLocked(ip, now) {
				m.queuePendingRouteLocked(candidate, ip, now)
				Log(LogLevel_DEBUG, LogType_CORE, "dynamic direct bypass route deferred until destination is idle: ", candidate.Host, " -> ", ip)
				continue
			}
			if err := m.routeManager.AddHostRoute(ctx, ip); err != nil {
				Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass add route failed: ", ip, " ", err)
				continue
			}
			delete(m.pendingRoutes, ip)
			if candidateReason == dynamicDirectBypassReasonRemoteFailure {
				if err := m.probeRemoteFailureDirectRoute(ctx, candidate, ip); err != nil {
					if deleteErr := m.routeManager.DeleteHostRoute(ctx, ip); deleteErr != nil {
						Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass delete failed remote fallback route failed: ", ip, " ", deleteErr)
					}
					m.markRemoteFailureProbeFailedLocked(candidate, ip, now)
					Log(dynamicDirectBypassRemoteProbeFailureLogLevel(false), LogType_CORE, "dynamic direct bypass remote fallback direct probe failed: ", candidate.Host, " -> ", ip, " ", err)
					continue
				}
				m.clearRemoteFailureProbeFailedLocked(candidate, ip)
			}
			m.routes[ip] = dynamicDirectBypassRoute{
				Host:      candidate.Host,
				IP:        ip.String(),
				Reason:    candidateReason,
				LastSeen:  now,
				ExpiresAt: now.Add(m.config.RouteTTL),
			}
			route := m.routes[ip]
			updateDynamicDirectBypassRouteProcess(&route, candidate.Process)
			m.routes[ip] = route
			changed = true
			routeRulesChanged = true
			m.clearFailedDirectRouteLocked(candidate.Host, ip, candidate.ProbePort)
			if candidateReason == dynamicDirectBypassReasonRemoteFailure {
				Log(LogLevel_INFO, LogType_CORE, "dynamic direct bypass remote fallback direct route added: ", candidate.Host, " -> ", ip)
			} else {
				Log(LogLevel_INFO, LogType_CORE, "dynamic direct bypass route added: ", candidate.Host, " -> ", ip)
			}
		}
	}
}

func (m *dynamicDirectBypassManager) notifyRoutesChanged() {
	if m != nil && m.onRoutesChanged != nil {
		m.onRoutesChanged()
	}
}

func (m *dynamicDirectBypassManager) shouldSkipRemoteFailureProbeLocked(
	candidate dynamicDirectBypassCandidate,
	ip netip.Addr,
	now time.Time,
) bool {
	if m == nil || len(m.failedRemoteProbes) == 0 {
		return false
	}
	failedAt, exists := m.failedRemoteProbes[dynamicDirectBypassRemoteProbeKeyFor(candidate, ip)]
	if !exists {
		return false
	}
	if now.Sub(failedAt) >= dynamicDirectBypassRemoteFailureProbeRetryInterval {
		delete(m.failedRemoteProbes, dynamicDirectBypassRemoteProbeKeyFor(candidate, ip))
		return false
	}
	Log(LogLevel_DEBUG, LogType_CORE, "dynamic direct bypass remote fallback direct probe skipped: ",
		candidate.Host, " -> ", ip)
	return true
}

func (m *dynamicDirectBypassManager) markRemoteFailureProbeFailedLocked(
	candidate dynamicDirectBypassCandidate,
	ip netip.Addr,
	now time.Time,
) {
	if m == nil {
		return
	}
	if m.failedRemoteProbes == nil {
		m.failedRemoteProbes = map[dynamicDirectBypassRemoteProbeKey]time.Time{}
	}
	m.failedRemoteProbes[dynamicDirectBypassRemoteProbeKeyFor(candidate, ip)] = now
}

func (m *dynamicDirectBypassManager) clearRemoteFailureProbeFailedLocked(
	candidate dynamicDirectBypassCandidate,
	ip netip.Addr,
) {
	if m == nil || len(m.failedRemoteProbes) == 0 {
		return
	}
	delete(m.failedRemoteProbes, dynamicDirectBypassRemoteProbeKeyFor(candidate, ip))
}

func dynamicDirectBypassRemoteProbeKeyFor(
	candidate dynamicDirectBypassCandidate,
	ip netip.Addr,
) dynamicDirectBypassRemoteProbeKey {
	return dynamicDirectBypassRouteProbeKey(candidate.Host, ip, candidate.ProbePort)
}

func dynamicDirectBypassRouteProbeKey(host string, ip netip.Addr, port uint16) dynamicDirectBypassRemoteProbeKey {
	if port == 0 {
		port = 443
	}
	return dynamicDirectBypassRemoteProbeKey{
		host: normalizeDynamicDirectBypassHost(host),
		ip:   ip,
		port: port,
	}
}

func dynamicDirectBypassFailedDirectRouteProbeKeys(
	host string,
	ip netip.Addr,
	port uint16,
) []dynamicDirectBypassRemoteProbeKey {
	key := dynamicDirectBypassRouteProbeKey(host, ip, port)
	if port != 0 {
		return []dynamicDirectBypassRemoteProbeKey{key}
	}
	httpKey := dynamicDirectBypassRouteProbeKey(host, ip, 80)
	return []dynamicDirectBypassRemoteProbeKey{key, httpKey}
}

func (m *dynamicDirectBypassManager) shouldSkipFailedDirectRouteLocked(
	host string,
	ip netip.Addr,
	port uint16,
	now time.Time,
) bool {
	if m == nil || len(m.failedDirectRoutes) == 0 {
		return false
	}
	for _, key := range dynamicDirectBypassFailedDirectRouteProbeKeys(host, ip, port) {
		failedAt, exists := m.failedDirectRoutes[key]
		if !exists {
			continue
		}
		if now.Sub(failedAt) >= dynamicDirectBypassRemoteFailureProbeRetryInterval {
			delete(m.failedDirectRoutes, key)
			continue
		}
		Log(LogLevel_DEBUG, LogType_CORE, "dynamic direct bypass failed direct route retry skipped: ",
			host, " -> ", ip)
		return true
	}
	return false
}

func (m *dynamicDirectBypassManager) markFailedDirectRouteLocked(
	host string,
	ip netip.Addr,
	port uint16,
	failedAt time.Time,
) {
	if m == nil {
		return
	}
	if m.failedDirectRoutes == nil {
		m.failedDirectRoutes = map[dynamicDirectBypassRemoteProbeKey]time.Time{}
	}
	m.failedDirectRoutes[dynamicDirectBypassRouteProbeKey(host, ip, port)] = failedAt
}

func (m *dynamicDirectBypassManager) clearFailedDirectRouteLocked(host string, ip netip.Addr, port uint16) {
	if m == nil || len(m.failedDirectRoutes) == 0 {
		return
	}
	for _, key := range dynamicDirectBypassFailedDirectRouteProbeKeys(host, ip, port) {
		delete(m.failedDirectRoutes, key)
	}
}

func (m *dynamicDirectBypassManager) probeRemoteFailureDirectRoute(
	ctx context.Context,
	candidate dynamicDirectBypassCandidate,
	ip netip.Addr,
) error {
	probe := m.directProbe
	if probe == nil {
		probe = defaultDynamicDirectBypassDirectProbe{}
	}
	port := candidate.ProbePort
	if port == 0 {
		port = 443
	}
	startedAt := time.Now()
	if err := probe.ProbeDirect(ctx, candidate.Host, ip, port); err != nil {
		Log(LogLevel_DEBUG, LogType_CORE, "TIMING DynamicDirectBypass remote fallback direct probe failed after ", time.Since(startedAt),
			" host=", candidate.Host, " ip=", ip, " port=", port)
		return err
	}
	Log(LogLevel_DEBUG, LogType_CORE, "TIMING DynamicDirectBypass remote fallback direct probe succeeded in ", time.Since(startedAt),
		" host=", candidate.Host, " ip=", ip, " port=", port)
	return nil
}

func (m *dynamicDirectBypassManager) cleanupExpired(ctx context.Context, now time.Time) {
	if m == nil || m.routeManager == nil {
		return
	}
	m.access.Lock()
	changed := false
	defer func() {
		if changed {
			m.saveCacheLocked()
		}
		m.access.Unlock()
		if changed {
			m.notifyRoutesChanged()
		}
	}()
	for ip, route := range m.routes {
		if now.Before(route.ExpiresAt) {
			continue
		}
		if !m.routeSwitchAllowedLocked(ip, now) {
			continue
		}
		if err := m.routeManager.DeleteHostRoute(ctx, ip); err != nil {
			Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass delete expired route failed: ", ip, " ", err)
		}
		delete(m.routes, ip)
		delete(m.pendingRouteDeletes, ip)
		changed = true
		Log(LogLevel_INFO, LogType_CORE, "dynamic direct bypass route expired: ", route.Host, " -> ", ip)
	}
}

func (m *dynamicDirectBypassManager) cleanupFailedDirectRoutes(
	ctx context.Context,
	connections []dynamicDirectBypassConnection,
	nowValues ...time.Time,
) {
	if m == nil || m.routeManager == nil || len(connections) == 0 {
		return
	}
	m.access.Lock()
	changed := false
	defer func() {
		if changed {
			m.saveCacheLocked()
		}
		m.access.Unlock()
		if changed {
			m.notifyRoutesChanged()
		}
	}()
	for _, connection := range connections {
		if !isDynamicDirectBypassFailedDirectConnection(connection) {
			continue
		}
		process := dynamicDirectBypassProcessFromConnection(connection)
		if isDynamicDirectBypassSelfProcess(process) {
			continue
		}
		ip := connection.Destination
		route, exists := m.routes[ip]
		if !exists {
			continue
		}
		host := normalizeDynamicDirectBypassHost(connection.Host)
		routeHost := normalizeDynamicDirectBypassHost(route.Host)
		if host != "" && routeHost != "" && host != routeHost {
			continue
		}
		failedAt := connection.ClosedAt
		if failedAt.IsZero() {
			failedAt = time.Now()
		}
		evaluationTime := failedAt
		if len(nowValues) > 0 {
			evaluationTime = nowValues[0]
		}
		failedHost := host
		if failedHost == "" {
			failedHost = routeHost
		}
		m.markFailedDirectRouteLocked(failedHost, ip, connection.DestinationPort, failedAt)
		if !m.routeSwitchAllowedLocked(ip, evaluationTime) {
			m.pendingRouteDeletes[ip] = dynamicDirectBypassPendingRouteDelete{
				Host:     route.Host,
				Upload:   connection.Upload,
				Download: connection.Download,
			}
			continue
		}
		if err := m.routeManager.DeleteHostRoute(ctx, ip); err != nil {
			Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass delete failed direct route failed: ", ip, " ", err)
		}
		delete(m.routes, ip)
		delete(m.pendingRouteDeletes, ip)
		changed = true
		Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass failed direct route removed: ",
			route.Host, " -> ", ip, " upload=", connection.Upload, " download=", connection.Download)
	}
}

func (m *dynamicDirectBypassManager) close(ctx context.Context) {
	if m == nil || m.routeManager == nil {
		return
	}
	startedAt := time.Now()
	m.access.Lock()
	defer m.access.Unlock()
	stageStartedAt := time.Now()
	m.saveCacheLocked()
	LogTiming("DynamicDirectBypass close save cache took ", time.Since(stageStartedAt),
		" routes=", len(m.routes), " total ", time.Since(startedAt))
	ips := make([]netip.Addr, 0, len(m.routes))
	for ip := range m.routes {
		ips = append(ips, ip)
	}
	sortAddrSlice(ips)
	stageStartedAt = time.Now()
	failures := deleteDynamicDirectBypassHostRoutes(ctx, m.routeManager, ips)
	LogTiming("DynamicDirectBypass close delete routes took ", time.Since(stageStartedAt),
		" routes=", len(ips), " failures=", len(failures), " total ", time.Since(startedAt))
	for _, ip := range ips {
		if err := failures[ip]; err != nil {
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
	// Learn new routes only from observed traffic. Windows DNS cache can contain
	// many stale addresses, so scanning it here would create synthetic probes
	// unrelated to the user's current access.
	connectionTicker := time.NewTicker(m.config.SampleInterval)
	defer connectionTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-connectionTicker.C:
			connections := snapshot()
			m.updateActiveDestinations(connections, now)
			m.applyPendingRouteDeletes(ctx, now)
			m.cleanupExpired(ctx, now)
			m.cleanupFailedDirectRoutes(ctx, connections, now)
			m.applyPendingRoutes(ctx, now)
			candidates := selectDynamicDirectBypassCandidatesAt(connections, m.config, m.config.ProtectedIPs, now)
			if len(candidates) > 0 {
				m.applyCandidates(ctx, candidates, now)
			}
		}
	}
}

func (m *dynamicDirectBypassManager) restoreInitial(ctx context.Context, now time.Time) {
	if m == nil || !m.config.Enabled {
		return
	}
	m.initialRestoreOnce.Do(func() {
		// Persisted routes were already validated by real traffic. Restore them
		// without probing, and let subsequent traffic refresh or remove them.
		if err := m.loadCacheAndApply(ctx, now); err != nil {
			Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass cache restore failed: ", err)
		}
	})
}

func (m *dynamicDirectBypassManager) applyDNSCacheCandidates(ctx context.Context, now time.Time) {
	if m == nil || m.dnsCache == nil || len(m.config.EagerSuffixes) == 0 {
		return
	}
	candidates, err := m.dnsCache.LookupCachedHostIPs(ctx, m.config.EagerSuffixes)
	if err != nil {
		Log(dynamicDirectBypassOptionalLookupFailureLogLevel(), LogType_CORE, "dynamic direct bypass dns cache lookup failed: ", err)
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
	if candidate.Reason == "remote-failure" && m.resolver != nil {
		if resolved, err := m.resolver.LookupNetIP(ctx, "ip4", candidate.Host); err == nil {
			for _, ip := range resolved {
				addIP(ip)
				if len(ips) >= m.config.MaxRoutesPerHost {
					break
				}
			}
		}
		if len(ips) > 0 {
			sortAddrSlice(ips)
			return ips
		}
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
	startedAt := time.Now()
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
	LogTiming("DynamicDirectBypass cache read took ", time.Since(startedAt),
		" cached=", len(cached), " bytes=", len(data))
	changed := false
	type cachedRouteIP struct {
		route dynamicDirectBypassRoute
		ip    netip.Addr
	}
	toApply := make([]cachedRouteIP, 0, len(cached))
	toDelete := make([]netip.Addr, 0)
	hostCounts := map[string]int{}
	for _, route := range cached {
		if isDynamicDirectBypassSelfRoute(route) {
			changed = true
			continue
		}
		if hconfig.IsDynamicDirectBypassExcludedHost(route.Host) {
			if ip, err := netip.ParseAddr(route.IP); err == nil {
				toDelete = append(toDelete, ip)
			}
			changed = true
			continue
		}
		ip, err := netip.ParseAddr(route.IP)
		if err != nil || !isDynamicDirectBypassRouteIP(ip, m.config.ProtectedIPs) {
			changed = true
			continue
		}
		if !shouldRestoreDynamicDirectBypassCachedRoute(route, m.config) {
			toDelete = append(toDelete, ip)
			changed = true
			continue
		}
		route.Reason = normalizeDynamicDirectBypassCachedRouteReason(route)
		if !now.Before(route.ExpiresAt) {
			toDelete = append(toDelete, ip)
			changed = true
			continue
		}
		host := normalizeDynamicDirectBypassHost(route.Host)
		if host != "" {
			if hostCounts[host] >= m.config.MaxRoutesPerHost {
				changed = true
				continue
			}
			hostCounts[host]++
		}
		if len(toApply) >= m.config.MaxRoutes {
			changed = true
			break
		}
		toApply = append(toApply, cachedRouteIP{route: route, ip: ip})
	}
	sortAddrSlice(toDelete)
	stageStartedAt := time.Now()
	deleteFailures := deleteDynamicDirectBypassHostRoutes(ctx, m.routeManager, toDelete)
	LogTiming("DynamicDirectBypass cache delete expired routes took ", time.Since(stageStartedAt),
		" routes=", len(toDelete), " failures=", len(deleteFailures),
		" total ", time.Since(startedAt))
	for _, ip := range toDelete {
		if err := deleteFailures[ip]; err != nil {
			Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass delete expired cached route failed: ", ip, " ", err)
		}
	}
	addrs := make([]netip.Addr, 0, len(toApply))
	for _, item := range toApply {
		addrs = append(addrs, item.ip)
	}
	stageStartedAt = time.Now()
	addFailures := addDynamicDirectBypassHostRoutes(ctx, m.routeManager, addrs)
	LogTiming("DynamicDirectBypass cache restore routes took ", time.Since(stageStartedAt),
		" routes=", len(addrs), " failures=", len(addFailures),
		" total ", time.Since(startedAt))
	m.access.Lock()
	defer m.access.Unlock()
	for _, item := range toApply {
		if err := addFailures[item.ip]; err != nil {
			Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass restore route failed: ", item.ip, " ", err)
			changed = true
			continue
		}
		if len(m.routes) >= m.config.MaxRoutes {
			changed = true
			break
		}
		m.routes[item.ip] = item.route
	}
	if changed {
		m.saveCacheLocked()
	}
	LogTiming("DynamicDirectBypass cache restore finished in ", time.Since(startedAt),
		" cached=", len(cached), " restored=", len(m.routes),
		" expired=", len(toDelete), " changed=", changed)
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
	startedAt := time.Now()
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
	LogTiming("DynamicDirectBypass cache cleanup read took ", time.Since(startedAt),
		" cached=", len(cached), " bytes=", len(data))
	toDelete := make([]netip.Addr, 0, len(cached))
	for _, route := range cached {
		ip, err := netip.ParseAddr(route.IP)
		if err != nil {
			continue
		}
		toDelete = append(toDelete, ip)
	}
	sortAddrSlice(toDelete)
	stageStartedAt := time.Now()
	failures := deleteDynamicDirectBypassHostRoutes(ctx, routeManager, toDelete)
	LogTiming("DynamicDirectBypass cache cleanup delete routes took ", time.Since(stageStartedAt),
		" routes=", len(toDelete), " failures=", len(failures),
		" total ", time.Since(startedAt))
	hosts := map[string]string{}
	for _, route := range cached {
		if _, err := netip.ParseAddr(route.IP); err == nil {
			hosts[route.IP] = route.Host
		}
	}
	for _, ip := range toDelete {
		if err := failures[ip]; err != nil {
			Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass delete cached route failed: ", ip, " ", err)
			continue
		}
		Log(LogLevel_INFO, LogType_CORE, "dynamic direct bypass cached route deleted: ", hosts[ip.String()], " -> ", ip)
	}
	LogTiming("DynamicDirectBypass cache cleanup finished in ", time.Since(startedAt),
		" cached=", len(cached), " deleted=", len(toDelete), " failures=", len(failures))
}

func addDynamicDirectBypassHostRoutes(
	ctx context.Context,
	routeManager dynamicDirectBypassRouteManager,
	addrs []netip.Addr,
) map[netip.Addr]error {
	if len(addrs) == 0 {
		return nil
	}
	if batchRouteManager, ok := routeManager.(dynamicDirectBypassBatchRouteManager); ok {
		return batchRouteManager.AddHostRoutes(ctx, uniqueDynamicDirectBypassAddrs(addrs))
	}
	failures := map[netip.Addr]error{}
	for _, addr := range uniqueDynamicDirectBypassAddrs(addrs) {
		if err := routeManager.AddHostRoute(ctx, addr); err != nil {
			failures[addr] = err
		}
	}
	return failures
}

func deleteDynamicDirectBypassHostRoutes(
	ctx context.Context,
	routeManager dynamicDirectBypassRouteManager,
	addrs []netip.Addr,
) map[netip.Addr]error {
	if len(addrs) == 0 {
		return nil
	}
	if batchRouteManager, ok := routeManager.(dynamicDirectBypassBatchRouteManager); ok {
		return batchRouteManager.DeleteHostRoutes(ctx, uniqueDynamicDirectBypassAddrs(addrs))
	}
	failures := map[netip.Addr]error{}
	for _, addr := range uniqueDynamicDirectBypassAddrs(addrs) {
		if err := routeManager.DeleteHostRoute(ctx, addr); err != nil {
			failures[addr] = err
		}
	}
	return failures
}

func uniqueDynamicDirectBypassAddrs(addrs []netip.Addr) []netip.Addr {
	if len(addrs) == 0 {
		return nil
	}
	seen := map[netip.Addr]struct{}{}
	unique := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if !addr.IsValid() {
			continue
		}
		if _, exists := seen[addr]; exists {
			continue
		}
		seen[addr] = struct{}{}
		unique = append(unique, addr)
	}
	sortAddrSlice(unique)
	return unique
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
			ID:              tracker.ID.String(),
			Host:            host,
			Destination:     tracker.Metadata.Destination.Addr,
			DestinationPort: tracker.Metadata.Destination.Port,
			Network:         tracker.Metadata.Network,
			Outbound:        tracker.Outbound,
			OutboundType:    tracker.OutboundType,
			Chain:           tracker.Chain,
			Upload:          loadDynamicDirectBypassCounter(tracker.Upload),
			Download:        loadDynamicDirectBypassCounter(tracker.Download),
			CreatedAt:       tracker.CreatedAt,
			ClosedAt:        tracker.ClosedAt,
			ProcessName:     processNameFromTracker(tracker),
			ProcessPath:     processPathFromTracker(tracker),
			ProcessID:       processIDFromTracker(tracker),
			UserName:        userNameFromTracker(tracker),
			PackageNames:    packageNamesFromTracker(tracker),
		})
	}
	return connections
}

func loadDynamicDirectBypassCounter(counter interface{ Load() int64 }) int64 {
	if counter == nil {
		return 0
	}
	return counter.Load()
}

type defaultDynamicDirectBypassDirectProbe struct{}

func (defaultDynamicDirectBypassDirectProbe) ProbeDirect(
	ctx context.Context,
	host string,
	ip netip.Addr,
	port uint16,
) error {
	if port == 0 {
		port = 443
	}
	probeCtx := ctx
	cancel := func() {}
	if _, hasDeadline := probeCtx.Deadline(); !hasDeadline {
		probeCtx, cancel = context.WithTimeout(probeCtx, dynamicDirectBypassRemoteFailureProbeTimeout)
	}
	defer cancel()

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(probeCtx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := probeCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if port != 443 {
		return nil
	}
	serverName := normalizeDynamicDirectBypassHost(host)
	if serverName == "" {
		return nil
	}
	if _, err := netip.ParseAddr(serverName); err == nil {
		return nil
	}
	tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName})
	if err := tlsConn.HandshakeContext(probeCtx); err != nil {
		return err
	}
	_ = tlsConn.Close()
	return nil
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

func isDynamicDirectBypassSelfRoute(route dynamicDirectBypassRoute) bool {
	return isDynamicDirectBypassSelfProcess(dynamicDirectBypassProcess{
		ProcessName: route.ProcessName,
		ProcessPath: route.ProcessPath,
	})
}

func isDynamicDirectBypassSelfProcess(process dynamicDirectBypassProcess) bool {
	processName := strings.ToLower(strings.TrimSpace(process.ProcessName))
	if processName == "" {
		processName = strings.ToLower(processNameFromPath(process.ProcessPath))
	}
	return processName == "hiddifycustom.exe" ||
		processName == "hiddifycustom" ||
		processName == "hiddify.exe" ||
		processName == "hiddify"
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
	config.RouteTTL = time.Duration(positiveIntFromCustom(custom[customDynamicDirectBypassTTLKey], int(config.RouteTTL/time.Second))) * time.Second
	config.MaxRoutes = positiveIntFromCustom(custom[customDynamicDirectBypassMaxRoutesKey], config.MaxRoutes)
	config.MaxRoutesPerHost = positiveIntFromCustom(custom[customDynamicDirectBypassMaxRoutesHostKey], config.MaxRoutesPerHost)
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

func positiveIntFromCustom(value any, fallback int) int {
	switch typed := value.(type) {
	case int:
		if typed > 0 {
			return typed
		}
	case int8:
		if typed > 0 {
			return int(typed)
		}
	case int16:
		if typed > 0 {
			return int(typed)
		}
	case int32:
		if typed > 0 {
			return int(typed)
		}
	case int64:
		if typed > 0 && typed <= int64(^uint(0)>>1) {
			return int(typed)
		}
	case uint:
		if typed > 0 {
			return int(typed)
		}
	case uint8:
		if typed > 0 {
			return int(typed)
		}
	case uint16:
		if typed > 0 {
			return int(typed)
		}
	case uint32:
		if typed > 0 {
			return int(typed)
		}
	case uint64:
		if typed > 0 && typed <= uint64(^uint(0)>>1) {
			return int(typed)
		}
	case float32:
		if typed >= 1 {
			return int(typed)
		}
	case float64:
		if typed >= 1 {
			return int(typed)
		}
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil && parsed > 0 {
			return parsed
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

func isDynamicDirectBypassUsableDirectConnection(connection dynamicDirectBypassConnection) bool {
	return isDynamicDirectBypassUsableDirectConnectionAt(connection, time.Now())
}

func isDynamicDirectBypassUsableDirectConnectionAt(connection dynamicDirectBypassConnection, now time.Time) bool {
	if !isDynamicDirectBypassDirectConnection(connection) {
		return false
	}
	if connection.Download <= dynamicDirectBypassDirectMinDownload {
		return false
	}
	if connection.ClosedAt.IsZero() {
		return true
	}
	age := now.Sub(connection.ClosedAt)
	return age >= 0 && age <= dynamicDirectBypassDirectSuccessMaxAge
}

func isDynamicDirectBypassFailedDirectConnection(connection dynamicDirectBypassConnection) bool {
	if !isDynamicDirectBypassDirectConnection(connection) {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(connection.Network), "tcp") {
		return false
	}
	if connection.DestinationPort != 443 && connection.DestinationPort != 80 {
		return false
	}
	if connection.ClosedAt.IsZero() {
		return false
	}
	if !connection.CreatedAt.IsZero() {
		duration := connection.ClosedAt.Sub(connection.CreatedAt)
		if duration < 0 || duration > dynamicDirectBypassRemoteFailureMaxDuration {
			return false
		}
	}
	return connection.Upload > 0 && connection.Download <= dynamicDirectBypassDirectMinDownload
}

func isDynamicDirectBypassRemoteFailureConnection(connection dynamicDirectBypassConnection) bool {
	if !strings.EqualFold(strings.TrimSpace(connection.Network), "tcp") {
		return false
	}
	if connection.DestinationPort != 443 && connection.DestinationPort != 80 {
		return false
	}
	if connection.ClosedAt.IsZero() {
		return false
	}
	if !connection.CreatedAt.IsZero() {
		duration := connection.ClosedAt.Sub(connection.CreatedAt)
		if duration < 0 || duration > dynamicDirectBypassRemoteFailureMaxDuration {
			return false
		}
	}
	if connection.Upload <= 0 || connection.Download > dynamicDirectBypassRemoteFailureMaxDownload {
		return false
	}
	outboundType := strings.ToLower(strings.TrimSpace(connection.OutboundType))
	switch outboundType {
	case "", constant.TypeDirect, constant.TypeBlock, constant.TypeDNS, constant.TypeSelector, constant.TypeURLTest, constant.TypeBalancer:
		return false
	}
	return true
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

func normalizeDynamicDirectBypassReason(reason string) string {
	if strings.EqualFold(strings.TrimSpace(reason), dynamicDirectBypassReasonRemoteFailure) {
		return dynamicDirectBypassReasonRemoteFailure
	}
	return dynamicDirectBypassReasonDirect
}

func isDynamicDirectBypassRemoteFailureAllowed(host string, config dynamicDirectBypassConfig) bool {
	return matchesDynamicDirectBypassSuffix(host, config.EagerSuffixes)
}

func shouldRestoreDynamicDirectBypassCachedRoute(route dynamicDirectBypassRoute, config dynamicDirectBypassConfig) bool {
	switch strings.ToLower(strings.TrimSpace(route.Reason)) {
	case dynamicDirectBypassReasonDirect:
		return true
	case dynamicDirectBypassReasonRemoteFailure:
		return isDynamicDirectBypassRemoteFailureAllowed(route.Host, config)
	case "":
		return isDynamicDirectBypassRemoteFailureAllowed(route.Host, config)
	default:
		return isDynamicDirectBypassRemoteFailureAllowed(route.Host, config)
	}
}

func normalizeDynamicDirectBypassCachedRouteReason(route dynamicDirectBypassRoute) string {
	switch strings.ToLower(strings.TrimSpace(route.Reason)) {
	case dynamicDirectBypassReasonDirect:
		return dynamicDirectBypassReasonDirect
	case dynamicDirectBypassReasonRemoteFailure:
		return dynamicDirectBypassReasonRemoteFailure
	default:
		return dynamicDirectBypassReasonRemoteFailure
	}
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
