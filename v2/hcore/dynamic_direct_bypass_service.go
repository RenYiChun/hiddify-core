package hcore

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

var (
	dynamicDirectBypassRouteReloadDelay             = 2 * time.Second
	dynamicDirectBypassRouteReloadIdleCheckInterval = 5 * time.Second
	dynamicDirectBypassRouteReloadMaxWait           = 10 * time.Second
	dynamicDirectBypassRouteReloadMu                sync.Mutex
	dynamicDirectBypassRouteReloadTimer             *time.Timer
	dynamicDirectBypassRouteReloadPendingSince      time.Time
	dynamicDirectBypassRouteReloadFunc              = reloadDynamicDirectBypassRouteRules
	dynamicDirectBypassRouteReloadActiveConnections = activeDynamicDirectBypassConnectionCount
)

type dynamicDirectBypassStartMode string

const (
	dynamicDirectBypassModeDisabled      dynamicDirectBypassStartMode = "disabled"
	dynamicDirectBypassModeSystemRoute   dynamicDirectBypassStartMode = "system-route"
	dynamicDirectBypassModeRuleCacheOnly dynamicDirectBypassStartMode = "rule-cache-only"
)

func startDynamicDirectBypassIfNeeded(options option.Options) {
	startedAt := time.Now()
	stopActiveDynamicDirectBypass(context.Background())
	if runtime.GOOS != "windows" {
		stageStartedAt := time.Now()
		cleanupDynamicDirectBypassCachedSystemRoutesWithDefaultManager(context.Background())
		LogTiming("DynamicDirectBypass startup cleanup without Windows took ", time.Since(stageStartedAt),
			" total ", time.Since(startedAt))
		return
	}
	config := dynamicDirectBypassConfigFromOptions(options)
	if !config.Enabled {
		stageStartedAt := time.Now()
		cleanupDynamicDirectBypassCachedSystemRoutesWithDefaultManager(context.Background())
		LogTiming("DynamicDirectBypass disabled cleanup took ", time.Since(stageStartedAt),
			" total ", time.Since(startedAt))
		return
	}
	mode := dynamicDirectBypassModeForOptions(options)
	Log(LogLevel_INFO, LogType_CORE, "dynamic direct bypass startup selected: mode=", mode,
		" hasTun=", hasTunInbound(options), " hasMixed=", hasMixedInbound(options),
		" inbounds=", len(options.Inbounds), " outbounds=", len(options.Outbounds),
		" routeRules=", dynamicDirectBypassRouteRuleCount(options),
		" dnsServers=", dynamicDirectBypassDNSServerCount(options))
	if mode == dynamicDirectBypassModeDisabled {
		stageStartedAt := time.Now()
		cleanupDynamicDirectBypassCachedSystemRoutesWithDefaultManager(context.Background())
		LogTiming("DynamicDirectBypass startup cleanup without supported inbound took ", time.Since(stageStartedAt),
			" total ", time.Since(startedAt))
		return
	}
	var routeManager dynamicDirectBypassRouteManager
	var dnsCache dynamicDirectBypassDNSCacheReader
	if mode == dynamicDirectBypassModeSystemRoute {
		stageStartedAt := time.Now()
		systemRouteManager, err := newSystemDynamicDirectBypassRouteManager()
		LogTiming("DynamicDirectBypass route manager init took ", time.Since(stageStartedAt),
			" total ", time.Since(startedAt))
		if err != nil {
			Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass disabled: ", err)
			return
		}
		routeManager = systemRouteManager
		dnsCache = newSystemDynamicDirectBypassDNSCacheReader()
	} else {
		routeManager = cacheOnlyDynamicDirectBypassRouteManager{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager := newDynamicDirectBypassManager(
		config,
		routeManager,
		net.DefaultResolver,
		dnsCache,
		filepath.Join(sWorkingPath, "data", "dynamic-direct-bypass-routes.json"),
	)
	manager.onRoutesChanged = scheduleDynamicDirectBypassRouteReload
	static.dynamicDirectBypassCancel = cancel
	static.dynamicDirectBypass = manager
	stageStartedAt := time.Now()
	manager.restoreInitial(ctx, time.Now())
	LogTiming("DynamicDirectBypass restore initial took ", time.Since(stageStartedAt),
		" total ", time.Since(startedAt))
	go manager.run(ctx, func() []dynamicDirectBypassConnection {
		trafficManager := static.TrafficManager()
		if trafficManager == nil {
			return nil
		}
		trackers := trafficManager.Connections()
		trackers = append(trackers, trafficManager.ClosedConnections()...)
		return dynamicDirectBypassConnectionsFromTrackers(trackers)
	})
	Log(LogLevel_INFO, LogType_CORE, "dynamic direct bypass started: mode=", mode, " strategy=all-direct",
		" ttl=", config.RouteTTL, " maxRoutes=", config.MaxRoutes, " maxRoutesPerHost=", config.MaxRoutesPerHost)
	LogTiming("DynamicDirectBypass startup finished in ", time.Since(startedAt))
}

func stopDynamicDirectBypass(ctx context.Context) {
	startedAt := time.Now()
	if stopActiveDynamicDirectBypass(ctx) {
		LogTiming("DynamicDirectBypass stop finished in ", time.Since(startedAt), " mode=active")
		return
	}
	stageStartedAt := time.Now()
	cleanupDynamicDirectBypassCachedSystemRoutesWithDefaultManager(ctx)
	LogTiming("DynamicDirectBypass stop cached cleanup took ", time.Since(stageStartedAt),
		" total ", time.Since(startedAt))
}

func stopActiveDynamicDirectBypass(ctx context.Context) bool {
	startedAt := time.Now()
	stopped := false
	if static.dynamicDirectBypassCancel != nil {
		static.dynamicDirectBypassCancel()
		static.dynamicDirectBypassCancel = nil
		stopped = true
	}
	if static.dynamicDirectBypass != nil {
		static.dynamicDirectBypass.close(ctx)
		static.dynamicDirectBypass = nil
		stopped = true
	}
	if stopped {
		cancelDynamicDirectBypassRouteReload()
		LogTiming("DynamicDirectBypass active stop took ", time.Since(startedAt))
	}
	return stopped
}

func scheduleDynamicDirectBypassRouteReload() {
	dynamicDirectBypassRouteReloadMu.Lock()
	if dynamicDirectBypassRouteReloadPendingSince.IsZero() {
		dynamicDirectBypassRouteReloadPendingSince = time.Now()
	}
	defer dynamicDirectBypassRouteReloadMu.Unlock()
	scheduleDynamicDirectBypassRouteReloadLocked(dynamicDirectBypassRouteReloadDelay)
	Log(LogLevel_INFO, LogType_CORE, "dynamic direct bypass route-rule reload scheduled")
}

func scheduleDynamicDirectBypassRouteReloadLocked(delay time.Duration) {
	if dynamicDirectBypassRouteReloadTimer != nil {
		dynamicDirectBypassRouteReloadTimer.Stop()
	}
	dynamicDirectBypassRouteReloadTimer = time.AfterFunc(delay, runScheduledDynamicDirectBypassRouteReload)
}

func runScheduledDynamicDirectBypassRouteReload() {
	now := time.Now()
	activeConnections := dynamicDirectBypassRouteReloadActiveConnections()
	dynamicDirectBypassRouteReloadMu.Lock()
	forceReload := !dynamicDirectBypassRouteReloadPendingSince.IsZero() &&
		now.Sub(dynamicDirectBypassRouteReloadPendingSince) >= dynamicDirectBypassRouteReloadMaxWait
	if activeConnections > 0 {
		if forceReload {
			dynamicDirectBypassRouteReloadTimer = nil
			dynamicDirectBypassRouteReloadPendingSince = time.Time{}
			dynamicDirectBypassRouteReloadMu.Unlock()
			Log(LogLevel_INFO, LogType_CORE,
				"dynamic direct bypass route-rule reload forced after wait: active connections=", activeConnections)
			dynamicDirectBypassRouteReloadFunc(dynamicDirectBypassRouteReloadContext())
			return
		}
		Log(LogLevel_INFO, LogType_CORE,
			"dynamic direct bypass route-rule reload pending: active connections=", activeConnections)
		scheduleDynamicDirectBypassRouteReloadLocked(dynamicDirectBypassRouteReloadIdleCheckInterval)
		dynamicDirectBypassRouteReloadMu.Unlock()
		return
	}
	dynamicDirectBypassRouteReloadTimer = nil
	dynamicDirectBypassRouteReloadPendingSince = time.Time{}
	dynamicDirectBypassRouteReloadMu.Unlock()
	dynamicDirectBypassRouteReloadFunc(dynamicDirectBypassRouteReloadContext())
}

func dynamicDirectBypassRouteReloadContext() context.Context {
	if static.BaseContext != nil {
		return static.BaseContext
	}
	return context.Background()
}

func cancelDynamicDirectBypassRouteReload() {
	dynamicDirectBypassRouteReloadMu.Lock()
	defer dynamicDirectBypassRouteReloadMu.Unlock()
	if dynamicDirectBypassRouteReloadTimer != nil {
		dynamicDirectBypassRouteReloadTimer.Stop()
		dynamicDirectBypassRouteReloadTimer = nil
	}
	dynamicDirectBypassRouteReloadPendingSince = time.Time{}
}

func reloadDynamicDirectBypassRouteRules(ctx context.Context) {
	startedAt := time.Now()
	static.lock.Lock()
	defer static.lock.Unlock()
	if static.StartedService == nil || static.previousStartRequest == nil {
		Log(LogLevel_DEBUG, LogType_CORE, "dynamic direct bypass route-rule reload skipped: service not started")
		return
	}
	Log(LogLevel_INFO, LogType_CORE, "dynamic direct bypass route-rule reload begin")
	options, err := BuildConfig(ctx, static.previousStartRequest)
	if err != nil {
		Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass route-rule reload build failed: ", err)
		return
	}
	Log(LogLevel_INFO, LogType_CORE, "dynamic direct bypass route-rule reload applying: hasTun=", hasTunInbound(*options),
		" hasMixed=", hasMixedInbound(*options), " inbounds=", len(options.Inbounds),
		" outbounds=", len(options.Outbounds), " routeRules=", dynamicDirectBypassRouteRuleCount(*options),
		" dnsServers=", dynamicDirectBypassDNSServerCount(*options))
	currentBuildConfigPath := filepath.Join(sWorkingPath, "data/current-config.json")
	if err := config.SaveCurrentConfig(ctx, currentBuildConfigPath, *options); err != nil {
		Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass route-rule reload save config failed: ", err)
	}
	if err := static.StartedService.StartOrReloadServiceOptions(*options); err != nil {
		Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass route-rule reload failed: ", err)
		return
	}
	LogTiming("DynamicDirectBypass route-rule reload took ", time.Since(startedAt))
}

func activeDynamicDirectBypassConnectionCount() int {
	trafficManager := static.TrafficManager()
	if trafficManager == nil {
		return 0
	}
	return len(trafficManager.Connections())
}

func cleanupDynamicDirectBypassCachedSystemRoutesWithDefaultManager(ctx context.Context) {
	if runtime.GOOS != "windows" {
		return
	}
	startedAt := time.Now()
	routeManager, err := newSystemDynamicDirectBypassRouteManager()
	LogTiming("DynamicDirectBypass cached cleanup route manager init took ", time.Since(startedAt))
	if err != nil {
		Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass cached route cleanup disabled: ", err)
		return
	}
	stageStartedAt := time.Now()
	cleanupDynamicDirectBypassCachedSystemRoutes(
		ctx,
		routeManager,
		filepath.Join(sWorkingPath, "data", "dynamic-direct-bypass-routes.json"),
	)
	LogTiming("DynamicDirectBypass cached cleanup routes took ", time.Since(stageStartedAt),
		" total ", time.Since(startedAt))
}

func hasTunInbound(options option.Options) bool {
	for _, inbound := range options.Inbounds {
		if inbound.Type == constant.TypeTun {
			return true
		}
	}
	return false
}

func dynamicDirectBypassModeForOptions(options option.Options) dynamicDirectBypassStartMode {
	if hasTunInbound(options) {
		return dynamicDirectBypassModeSystemRoute
	}
	if hasMixedInbound(options) {
		return dynamicDirectBypassModeRuleCacheOnly
	}
	return dynamicDirectBypassModeDisabled
}

func hasMixedInbound(options option.Options) bool {
	for _, inbound := range options.Inbounds {
		if inbound.Type == constant.TypeMixed {
			return true
		}
	}
	return false
}

func dynamicDirectBypassRouteRuleCount(options option.Options) int {
	if options.Route == nil {
		return 0
	}
	return len(options.Route.Rules)
}

func dynamicDirectBypassDNSServerCount(options option.Options) int {
	if options.DNS == nil {
		return 0
	}
	return len(options.DNS.Servers)
}
