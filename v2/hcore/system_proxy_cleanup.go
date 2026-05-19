package hcore

import (
	"net/netip"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type windowsSystemProxyState struct {
	enabled bool
	server  string
}

func cleanupStaleSystemProxyForTunIfNeeded(options option.Options) {
	state, err := currentWindowsSystemProxyState()
	if err != nil {
		Log(LogLevel_WARNING, LogType_CORE, "stale system proxy cleanup skipped: ", err)
		return
	}
	if !shouldClearStaleSystemProxyForTun(options, state) {
		return
	}
	if err := clearWindowsSystemProxy(); err != nil {
		Log(LogLevel_WARNING, LogType_CORE, "stale system proxy cleanup failed: ", err)
		return
	}
	Log(LogLevel_INFO, LogType_CORE, "stale system proxy cleared for TUN mode: ", state.server)
}

func shouldClearStaleSystemProxyForTun(options option.Options, state windowsSystemProxyState) bool {
	if !state.enabled || !hasTunInbound(options) || hasSystemProxyInbound(options) {
		return false
	}
	expected := localMixedProxyServers(options)
	if len(expected) == 0 {
		return false
	}
	actual := normalizeSystemProxyServers(state.server)
	if len(actual) == 0 {
		return false
	}
	for _, server := range actual {
		if _, ok := expected[server]; !ok {
			return false
		}
	}
	return true
}

func hasSystemProxyInbound(options option.Options) bool {
	for _, inbound := range options.Inbounds {
		mixed, ok := inbound.Options.(*option.HTTPMixedInboundOptions)
		if !ok {
			continue
		}
		if mixed.SetSystemProxy {
			return true
		}
	}
	return false
}

func localMixedProxyServers(options option.Options) map[string]struct{} {
	servers := map[string]struct{}{}
	for _, inbound := range options.Inbounds {
		if inbound.Type != C.TypeMixed && inbound.Type != C.TypeHTTP {
			continue
		}
		mixed, ok := inbound.Options.(*option.HTTPMixedInboundOptions)
		if !ok || mixed.ListenPort == 0 {
			continue
		}
		host := "127.0.0.1"
		if mixed.Listen != nil {
			host = netip.Addr(*mixed.Listen).String()
		}
		port := strconv.Itoa(int(mixed.ListenPort))
		if host == "::1" {
			servers["[::1]:"+port] = struct{}{}
			continue
		}
		servers[host+":"+port] = struct{}{}
	}
	return servers
}

func normalizeSystemProxyServers(server string) []string {
	parts := strings.Split(server, ";")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		if _, after, ok := strings.Cut(part, "="); ok {
			part = after
		}
		part = strings.TrimPrefix(part, "http://")
		part = strings.TrimPrefix(part, "https://")
		part = strings.TrimPrefix(part, "socks://")
		part = strings.TrimSuffix(part, "/")
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}
