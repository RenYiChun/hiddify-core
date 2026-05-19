package hcore

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"time"

	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func startDynamicDirectBypassIfNeeded(options option.Options) {
	stopDynamicDirectBypass(context.Background())
	if runtime.GOOS != "windows" || !hasTunInbound(options) {
		cleanupDynamicDirectBypassCachedSystemRoutesWithDefaultManager(context.Background())
		return
	}
	config := dynamicDirectBypassConfigFromOptions(options)
	if !config.Enabled {
		return
	}
	routeManager, err := newSystemDynamicDirectBypassRouteManager()
	if err != nil {
		Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass disabled: ", err)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager := newDynamicDirectBypassManager(
		config,
		routeManager,
		net.DefaultResolver,
		newSystemDynamicDirectBypassDNSCacheReader(),
		filepath.Join(sWorkingPath, "data", "dynamic-direct-bypass-routes.json"),
	)
	static.dynamicDirectBypassCancel = cancel
	static.dynamicDirectBypass = manager
	manager.restoreInitial(ctx, time.Now())
	go manager.run(ctx, func() []dynamicDirectBypassConnection {
		trafficManager := static.TrafficManager()
		if trafficManager == nil {
			return nil
		}
		return dynamicDirectBypassConnectionsFromTrackers(trafficManager.Connections())
	})
	Log(LogLevel_INFO, LogType_CORE, "dynamic direct bypass started: mode=all-direct",
		" ttl=", config.RouteTTL, " maxRoutes=", config.MaxRoutes, " maxRoutesPerHost=", config.MaxRoutesPerHost)
}

func stopDynamicDirectBypass(ctx context.Context) {
	if static.dynamicDirectBypassCancel != nil {
		static.dynamicDirectBypassCancel()
		static.dynamicDirectBypassCancel = nil
	}
	if static.dynamicDirectBypass != nil {
		static.dynamicDirectBypass.close(ctx)
		static.dynamicDirectBypass = nil
	}
	cleanupDynamicDirectBypassCachedSystemRoutesWithDefaultManager(ctx)
}

func cleanupDynamicDirectBypassCachedSystemRoutesWithDefaultManager(ctx context.Context) {
	if runtime.GOOS != "windows" {
		return
	}
	routeManager, err := newSystemDynamicDirectBypassRouteManager()
	if err != nil {
		Log(LogLevel_WARNING, LogType_CORE, "dynamic direct bypass cached route cleanup disabled: ", err)
		return
	}
	cleanupDynamicDirectBypassCachedSystemRoutes(
		ctx,
		routeManager,
		filepath.Join(sWorkingPath, "data", "dynamic-direct-bypass-routes.json"),
	)
}

func hasTunInbound(options option.Options) bool {
	for _, inbound := range options.Inbounds {
		if inbound.Type == constant.TypeTun {
			return true
		}
	}
	return false
}
