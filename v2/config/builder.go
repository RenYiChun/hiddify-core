package config

import (
	context "context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	sync "sync"
	"time"

	"github.com/hiddify/hiddify-core/v2/hutils"
	mDNS "github.com/miekg/dns"
	C "github.com/sagernet/sing-box/constant"
	sdns "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/wireguard-go/hiddify"
)

const (
	DNSRemoteTag         = "dns-remote"
	DNSRemoteTagFallback = "dns-remote-fallback"
	DNSLocalTag          = "dns-local"
	DNSStaticTag         = "dns-static"
	DNSDirectTag         = "dns-direct"
	DNSRemoteNoWarpTag   = "dns-remote-no-warp"
	// DNSBlockTag        = "dns-block"
	DNSFakeTag         = "dns-fake"
	DNSTricksDirectTag = "dns-trick-direct"
	// DNSMultiDirectTag  = "dns-multi-direct"
	// DNSMultiRemoteTag  = "dns-multi-remote"
	DNSMultiDirectTag = "dns-direct"
	DNSMultiRemoteTag = "dns-remote"

	OutboundDirectTag = "direct §hide§"
	OutboundBypassTag = "bypass §hide§"
	// OutboundBlockTag          = "block §hide§"
	OutboundSelectTag         = "select"
	OutboundURLTestTag        = "lowest"
	OutboundRoundRobinTag     = "balance"
	OutboundDNSTag            = "dns-out §hide§"
	OutboundDirectFragmentTag = "direct-fragment §hide§"

	WARPConfigTag = "🔒 WARP"

	InboundTUNTag    = "tun-in"
	InboundMixedTag  = "mixed-in"
	InboundTProxy    = "tproxy-in"
	InboundRedirect  = "redirect-in"
	InboundDirectTag = "dns-in"
)

var (
	OutboundMainDetour       = OutboundSelectTag
	OutboundWARPConfigDetour = OutboundDirectFragmentTag
	PredefinedOutboundTags   = []string{OutboundDirectTag, OutboundBypassTag, OutboundSelectTag, OutboundURLTestTag, OutboundDNSTag, OutboundDirectFragmentTag, WARPConfigTag}
)

// TODO include selectors
func BuildConfig(ctx context.Context, hopts *HiddifyOptions, inputOpt *ReadOptions) (*option.Options, error) {

	input, err := ReadSingOptions(ctx, inputOpt)
	if err != nil {
		return nil, err
	}

	var options option.Options
	if hopts.EnableFullConfig {
		options.Inbounds = input.Inbounds
		options.DNS = input.DNS
		options.Route = input.Route
	}

	setExperimental(&options, hopts)

	setLog(&options, hopts)
	setInbound(&options, hopts)
	staticIPs := make(map[string][]string)
	// staticIPs["api.cloudflareclient.com"] = []string{"104.16.192.82", "2606:4700::6810:1854", getRandomWarpIP()}
	// setNTP(&options)
	if err := setOutbounds(&options, input, hopts, &staticIPs); err != nil {
		return nil, err
	}
	setTunRouteExcludes(&options, hopts)
	if err := setDns(&options, hopts, &staticIPs); err != nil {
		return nil, err
	}

	if err := setRoutingOptions(&options, hopts); err != nil {
		return nil, err
	}

	setHiddifyCustomOptions(&options, hopts)

	return &options, nil
}

func setNTP(options *option.Options) {
	options.NTP = &option.NTPOptions{
		Enabled:       true,
		ServerOptions: option.ServerOptions{ServerPort: 123, Server: "time.apple.com"},
		Interval:      badoption.Duration(12 * time.Hour),
		DialerOptions: option.DialerOptions{
			Detour: OutboundDirectTag,
		},
	}
}

func getHostnameIfNotIP(inp string) (string, error) {
	if inp == "" {
		return "", fmt.Errorf("empty hostname: %s", inp)
	}
	if net.ParseIP(strings.Trim(inp, "[]")) == nil {
		inp2 := inp
		if !strings.Contains(inp, "://") {
			inp2 = "http://" + inp
		}
		u, err := url.Parse(inp2)
		if err != nil {
			return inp, nil
		}
		if net.ParseIP(strings.Trim(u.Host, "[]")) == nil {
			return u.Host, nil
		}
	}
	return "", fmt.Errorf("not a hostname: %s", inp)
}

func setTunRouteExcludes(options *option.Options, hopt *HiddifyOptions) {
	if options == nil || hopt == nil || !hopt.EnableTun {
		return
	}
	excludes := collectTunRouteExcludeAddresses(options, hopt)
	if len(excludes) == 0 {
		return
	}
	for i := range options.Inbounds {
		if options.Inbounds[i].Tag != InboundTUNTag {
			continue
		}
		tunOptions, ok := options.Inbounds[i].Options.(*option.TunInboundOptions)
		if !ok {
			continue
		}
		tunOptions.RouteExcludeAddress = appendUniqueRouteExcludePrefixes(tunOptions.RouteExcludeAddress, excludes)
	}
}

func collectTunRouteExcludeAddresses(options *option.Options, hopt *HiddifyOptions) []netip.Prefix {
	seen := map[string]netip.Prefix{}
	addPrefix := func(prefixString string) {
		prefix, err := netip.ParsePrefix(prefixString)
		if err != nil {
			return
		}
		seen[prefix.String()] = prefix
	}
	addAddress := func(address string) {
		prefix, ok := routeExcludePrefixFromAddress(address)
		if !ok {
			return
		}
		seen[prefix.String()] = prefix
	}

	if hopt.BypassLAN {
		for _, prefix := range []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		} {
			addPrefix(prefix)
		}
	}

	addAddress(hopt.DirectDnsAddress)
	addAddress(hopt.RemoteDnsAddress)
	for _, outbound := range getAllOutboundsOptions(options) {
		server, ok := outbound.(option.ServerOptionsWrapper)
		if !ok {
			continue
		}
		addAddress(server.TakeServerOptions().Server)
	}

	prefixes := make([]netip.Prefix, 0, len(seen))
	for _, prefix := range seen {
		prefixes = append(prefixes, prefix)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		return prefixes[i].String() < prefixes[j].String()
	})
	return prefixes
}

func routeExcludePrefixFromAddress(address string) (netip.Prefix, bool) {
	host := strings.TrimSpace(address)
	if host == "" {
		return netip.Prefix{}, false
	}
	if strings.Contains(host, "://") {
		parsedURL, err := url.Parse(host)
		if err != nil {
			return netip.Prefix{}, false
		}
		host = parsedURL.Hostname()
	} else if splitHost, _, err := net.SplitHostPort(host); err == nil {
		host = splitHost
	}
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, addr.BitLen()), true
}

func appendUniqueRouteExcludePrefixes(existing []netip.Prefix, additions []netip.Prefix) []netip.Prefix {
	seen := map[string]struct{}{}
	result := make([]netip.Prefix, 0, len(existing)+len(additions))
	for _, prefix := range existing {
		seen[prefix.String()] = struct{}{}
		result = append(result, prefix)
	}
	for _, prefix := range additions {
		if _, ok := seen[prefix.String()]; ok {
			continue
		}
		seen[prefix.String()] = struct{}{}
		result = append(result, prefix)
	}
	return result
}

const (
	customRouteDirectConnectionLimitKey       = "hiddify-route-direct-connection-limit"
	customRouteProxyConnectionLimitKey        = "hiddify-route-proxy-connection-limit"
	customDynamicDirectBypassEnabledKey       = "hiddify-dynamic-direct-bypass-enabled"
	customDynamicDirectBypassTTLKey           = "hiddify-dynamic-direct-bypass-ttl"
	customDynamicDirectBypassMaxRoutesKey     = "hiddify-dynamic-direct-bypass-max-routes"
	customDynamicDirectBypassMaxRoutesHostKey = "hiddify-dynamic-direct-bypass-max-routes-per-host"
	customDynamicDirectBypassEagerSuffixesKey = "hiddify-dynamic-direct-bypass-eager-domain-suffixes"
)

func setHiddifyCustomOptions(options *option.Options, hopt *HiddifyOptions) {
	if options == nil || hopt == nil {
		return
	}
	custom := map[string]any{}
	if options.Custom != nil {
		for key, value := range *options.Custom {
			custom[key] = value
		}
	}
	custom[customRouteDirectConnectionLimitKey] = normalizeRouteConnectionLimit(
		hopt.DirectRouteConnectionLimit,
		DefaultDirectRouteConnectionLimit,
	)
	custom[customRouteProxyConnectionLimitKey] = normalizeRouteConnectionLimit(
		hopt.ProxyRouteConnectionLimit,
		DefaultProxyRouteConnectionLimit,
	)
	custom[customDynamicDirectBypassEnabledKey] = hopt.EnableDynamicDirectBypass
	custom[customDynamicDirectBypassTTLKey] = normalizePositiveInt(
		int(hopt.DynamicDirectBypassTTL),
		int(DefaultDynamicDirectBypassTTL),
	)
	custom[customDynamicDirectBypassMaxRoutesKey] = normalizePositiveInt(
		hopt.DynamicDirectBypassMaxRoutes,
		DefaultDynamicDirectBypassMaxRoutes,
	)
	custom[customDynamicDirectBypassMaxRoutesHostKey] = normalizePositiveInt(
		hopt.DynamicDirectBypassMaxRoutesHost,
		DefaultDynamicDirectBypassMaxRoutesHost,
	)
	custom[customDynamicDirectBypassEagerSuffixesKey] = configuredDirectDomainSuffixRules(hopt)
	options.Custom = &custom
}

func effectiveDomainStrategyForIPv6Mode(configured option.DomainStrategy, hopt *HiddifyOptions) option.DomainStrategy {
	if hopt != nil &&
		hopt.IPv6Mode == option.DomainStrategy(C.DomainStrategyIPv4Only) &&
		configured == option.DomainStrategy(C.DomainStrategyAsIS) {
		return option.DomainStrategy(C.DomainStrategyIPv4Only)
	}
	return configured
}

func effectiveDirectDNSDomainStrategy(hopt *HiddifyOptions) option.DomainStrategy {
	if hopt == nil {
		return option.DomainStrategy(C.DomainStrategyAsIS)
	}
	return effectiveDomainStrategyForIPv6Mode(hopt.DirectDnsDomainStrategy, hopt)
}

func effectiveRemoteDNSDomainStrategy(hopt *HiddifyOptions) option.DomainStrategy {
	if hopt == nil {
		return option.DomainStrategy(C.DomainStrategyAsIS)
	}
	return effectiveDomainStrategyForIPv6Mode(hopt.RemoteDnsDomainStrategy, hopt)
}

func normalizeRouteConnectionLimit(limit int, defaultLimit int) int {
	if limit < 1 {
		return defaultLimit
	}
	if defaultLimit == DefaultDirectRouteConnectionLimit && limit == 512 {
		return defaultLimit
	}
	if defaultLimit == DefaultProxyRouteConnectionLimit && limit == 128 {
		return defaultLimit
	}
	return limit
}

func normalizePositiveInt(value int, defaultValue int) int {
	if value < 1 {
		return defaultValue
	}
	return value
}

func setOutbounds(options *option.Options, input *option.Options, opt *HiddifyOptions, staticIPs *map[string][]string) error {
	var outbounds []option.Outbound
	var endpoints []option.Endpoint
	var tags []string
	// OutboundMainProxyTag = OutboundSelectTag
	// inbound==warp over proxies
	// outbound==proxies over warp
	OutboundMainDetour = OutboundSelectTag
	OutboundWARPConfigDetour = OutboundDirectFragmentTag
	hasPsiphon := false
	for _, out := range input.Outbounds {

		if contains(PredefinedOutboundTags, out.Tag) {
			continue
		}
		outbound, err := patchOutbound(out, *opt, staticIPs)
		if err != nil {
			return err
		}
		out = *outbound

		switch out.Type {
		case C.TypeBlock, C.TypeDNS:
			continue
		case C.TypeSelector, C.TypeURLTest:
			continue
		case C.TypeCustom:
			continue
		default:

			if contains([]string{"direct", "bypass", "block"}, out.Tag) {
				continue
			}
			if out.Type == C.TypePsiphon {
				if hasPsiphon {
					continue
				}
				hasPsiphon = true
			}
			if !strings.Contains(out.Tag, "§hide§") {
				tags = append(tags, out.Tag)
			}
			// OutboundWARPConfigDetour = OutboundSelectTag
			out = *patchHiddifyWarpFromConfig(&out, *opt)
			outbounds = append(outbounds, out)
		}
	}

	if opt.Warp.EnableWarp {
		// wg := getOrGenerateWarpLocallyIfNeeded(&opt.Warp)

		// out, err := GenerateWarpSingbox(wg, opt.Warp.CleanIP, opt.Warp.CleanPort, &option.WireGuardHiddify{
		// 	FakePackets:      opt.Warp.FakePackets,
		// 	FakePacketsSize:  opt.Warp.FakePacketSize,
		// 	FakePacketsDelay: opt.Warp.FakePacketDelay,
		// 	FakePacketsMode:  opt.Warp.FakePacketMode,
		// })
		out, err := GenerateWarpSingboxNew("p1", &hiddify.NoiseOptions{})
		if err != nil {
			return fmt.Errorf("failed to generate warp config: %v", err)
		}
		out.Tag = WARPConfigTag
		if opts, ok := out.Options.(*option.WireGuardWARPEndpointOptions); ok {
			if opt.Warp.Mode == "warp_over_proxy" {
				opts.Detour = OutboundSelectTag
				opts.MTU = 1280
			} else {
				opts.Detour = OutboundDirectTag
				opt.MTU = max(opt.MTU, 1340)
			}

		}

		OutboundMainDetour = WARPConfigTag
		// patchWarp(out, opt, true, nil)
		out, err = patchEndpoint(out, *opt, staticIPs)
		if err != nil {
			return err
		}
		endpoints = append(endpoints, *out)
	}
	for _, end := range input.Endpoints {
		if contains(PredefinedOutboundTags, end.Tag) {
			continue
		}
		if opt.Warp.EnableWarp {
			if end.Type == C.TypeWARP {
				if opts, ok := end.Options.(*option.WireGuardWARPEndpointOptions); ok {
					if opts.UniqueIdentifier == "p1" {
						continue
					}
					if opt.Warp.EnableWarp && opt.Warp.Mode == "warp_over_proxy" {
						opt.MTU = max(opt.MTU, 1340)
					}
				}
			}
			if end.Type == C.TypeWireGuard {
				if opts, ok := end.Options.(*option.WireGuardEndpointOptions); ok {
					if opts.PrivateKey == opt.Warp.WireguardConfig.PrivateKey {
						continue
					}
					if opt.Warp.EnableWarp && opt.Warp.Mode == "warp_over_proxy" {
						opt.MTU = max(opt.MTU, 1340)
					}
				}
			}
		}

		out, err := patchEndpoint(&end, *opt, staticIPs)
		if err != nil {
			return err
		}

		if !strings.Contains(out.Tag, "§hide§") {
			tags = append(tags, out.Tag)
		}

		endpoints = append(endpoints, *out)
	}
	if len(opt.ConnectionTestUrls) == 0 {
		opt.ConnectionTestUrls = preferredConnectionTestURLs(opt.ConnectionTestUrl)
	}
	// urlTest := option.Outbound{
	// 	Type: C.TypeURLTest,
	// 	Tag:  OutboundURLTestTag,
	// 	Options: &option.URLTestOutboundOptions{
	// 		Outbounds: tags,
	// 		URL:       opt.ConnectionTestUrl,
	// 		URLs:      opt.ConnectionTestUrls,
	// 		Interval:  badoption.Duration(opt.URLTestInterval.Duration()),
	// 		// IdleTimeout: badoption.Duration(opt.URLTestIdleTimeout.Duration()),
	// 		Tolerance:                 1,
	// 		IdleTimeout:               badoption.Duration(opt.URLTestInterval.Duration().Nanoseconds() * 3),
	// 		InterruptExistConnections: true,
	// 	},
	// }
	urlTest := option.Outbound{
		Type: C.TypeBalancer,
		Tag:  OutboundURLTestTag,
		Options: &option.BalancerOutboundOptions{
			Outbounds:            tags,
			Strategy:             "lowest-delay",
			DelayAcceptableRatio: 2,
			// URL:       opt.ConnectionTestUrl,
			// URLs:      opt.ConnectionTestUrls,
			// Interval:  badoption.Duration(opt.URLTestInterval.Duration()),
			// IdleTimeout: badoption.Duration(opt.URLTestIdleTimeout.Duration()),
			Tolerance: 1,
			// IdleTimeout:               badoption.Duration(opt.URLTestInterval.Duration().Nanoseconds() * 3),
			InterruptExistConnections: false,
		},
	}

	balancerStrategy := opt.BalancerStrategy
	if balancerStrategy == "" {
		balancerStrategy = DefaultBalancerStrategy
	}

	balancer := option.Outbound{
		Type: C.TypeBalancer,
		Tag:  OutboundRoundRobinTag,
		Options: &option.BalancerOutboundOptions{
			Outbounds:            tags,
			Strategy:             balancerStrategy,
			DelayAcceptableRatio: 2,
			// URL:       opt.ConnectionTestUrl,
			// URLs:      opt.ConnectionTestUrls,
			// Interval:  badoption.Duration(opt.URLTestInterval.Duration()),
			// IdleTimeout: badoption.Duration(opt.URLTestIdleTimeout.Duration()),
			Tolerance: 1,
			// IdleTimeout:               badoption.Duration(opt.URLTestInterval.Duration().Nanoseconds() * 3),
			InterruptExistConnections: false,
		},
	}
	defaultSelect := tags[0]

	for _, tag := range tags {
		if strings.Contains(tag, "§default§") {
			defaultSelect = "§default§"
		}
	}

	selectorTags := tags
	if len(tags) > 1 {
		if OutboundMainDetour == WARPConfigTag {
			outbounds = append([]option.Outbound{urlTest}, outbounds...)
			selectorTags = append([]string{urlTest.Tag}, selectorTags...)
			defaultSelect = urlTest.Tag
		} else {
			outbounds = append([]option.Outbound{balancer, urlTest}, outbounds...)
			selectorTags = append([]string{urlTest.Tag, balancer.Tag}, selectorTags...)
			defaultSelect = urlTest.Tag

		}
	}
	selector := option.Outbound{
		Type: C.TypeSelector,
		Tag:  OutboundSelectTag,
		Options: &option.SelectorOutboundOptions{
			Outbounds:                 selectorTags,
			Default:                   defaultSelect,
			InterruptExistConnections: true,
		},
	}
	outbounds = append([]option.Outbound{selector}, outbounds...)

	options.Endpoints = endpoints
	options.Outbounds = append(
		outbounds,
		[]option.Outbound{
			{
				Tag:  OutboundDirectTag,
				Type: C.TypeDirect,
				Options: &option.DirectOutboundOptions{
					DialerOptions: option.DialerOptions{
						ConnectTimeout: badoption.Duration(3 * time.Second),
					},
				},
			},
			{
				Tag:  OutboundDirectFragmentTag,
				Type: C.TypeDirect,
				Options: &option.DirectOutboundOptions{
					DialerOptions: option.DialerOptions{
						TCPFastOpen:    false,
						ConnectTimeout: badoption.Duration(3 * time.Second),

						TLSFragment: option.TLSFragmentOptions{
							Enabled: true,
							Size:    opt.TLSTricks.FragmentSize,
							Sleep:   opt.TLSTricks.FragmentSleep,
						},
					},
				},
			},
		}...,
	)

	return nil
}

func isBlockedConnectionTestUrl(d string) bool {
	u, err := url.Parse(d)
	if err != nil {
		return false
	}
	return isBlockedDomain(u.Host)
}

func preferredConnectionTestURLs(configured string) []string {
	return uniqueStrings([]string{
		"https://cp.cloudflare.com",
		"https://www.google.com/generate_204",
		"https://google.com/generate_204",
		configured,
		"http://captive.apple.com/generate_204",
	})
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func setExperimental(options *option.Options, hopt *HiddifyOptions) {
	if len(hopt.ConnectionTestUrls) == 0 {
		hopt.ConnectionTestUrls = preferredConnectionTestURLs(hopt.ConnectionTestUrl)
	}
	if hopt.EnableClashApi {
		if hopt.ClashApiSecret == "" {
			hopt.ClashApiSecret = generateRandomString(16)
		}
		options.Experimental = &option.ExperimentalOptions{
			UnifiedDelay: &option.UnifiedDelayOptions{
				Enabled: true,
			},
			ClashAPI: &option.ClashAPIOptions{
				ExternalController: fmt.Sprintf("%s:%d", "127.0.0.1", hopt.ClashApiPort),
				Secret:             hopt.ClashApiSecret,
			},

			CacheFile: &option.CacheFileOptions{
				Enabled:         true,
				StoreWARPConfig: true,
				Path:            "data/clash.db",
			},

			Monitoring: &option.MonitoringOptions{
				URLs:           hopt.ConnectionTestUrls,
				Interval:       badoption.Duration(hopt.URLTestInterval.Duration()),
				Workers:        3,
				DebounceWindow: badoption.Duration(time.Millisecond * 500),
				IdleTimeout:    badoption.Duration(hopt.URLTestInterval.Duration().Nanoseconds() * 3),
				URLTestLogFile: "data/url-test.log",
			},
		}
	}
}

func setLog(options *option.Options, opt *HiddifyOptions) {
	options.Log = &option.LogOptions{
		Level:        opt.LogLevel,
		Output:       opt.LogFile,
		Disabled:     false,
		Timestamp:    false,
		DisableColor: true,
	}
}
func isIPv6Supported() bool {
	if C.IsIos || C.IsDarwin {
		return true
	}
	_, err := net.ResolveIPAddr("ip6", "::1")
	return err == nil
}

func shouldEnableIPv6(hopt *HiddifyOptions) bool {
	if hopt.IPv6Mode == option.DomainStrategy(C.DomainStrategyIPv4Only) {
		return false
	}
	return isIPv6Supported()
}

func defaultDomainResolverServer(hopt *HiddifyOptions) string {
	if hopt.EnableTun || hopt.EnableTunService {
		return DNSLocalTag
	}
	return DNSMultiDirectTag
}

func directDNSRuleServers(hopt *HiddifyOptions) []string {
	return []string{DNSMultiDirectTag}
}

func appendDirectDNSRules(
	dnsRules []option.DefaultDNSRule,
	rawRule option.RawDefaultDNSRule,
	hopt *HiddifyOptions,
) []option.DefaultDNSRule {
	return appendDirectDNSRulesWithTerminalFallback(dnsRules, rawRule, hopt, false)
}

func appendDirectDNSRulesWithTerminalFallback(
	dnsRules []option.DefaultDNSRule,
	rawRule option.RawDefaultDNSRule,
	hopt *HiddifyOptions,
	terminalBypassIfFailed bool,
) []option.DefaultDNSRule {
	servers := directDNSRuleServers(hopt)
	for index, server := range servers {
		bypassIfFailed := true
		if index == len(servers)-1 {
			bypassIfFailed = terminalBypassIfFailed
		}
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: rawRule,
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server:         server,
					Strategy:       effectiveDirectDNSDomainStrategy(hopt),
					RewriteTTL:     &DEFAULT_DNS_TTL,
					BypassIfFailed: bypassIfFailed,
				},
			},
		})
	}
	return dnsRules
}

func appendLocalReverseDNSRules(dnsRules []option.DefaultDNSRule) []option.DefaultDNSRule {
	return append(dnsRules, option.DefaultDNSRule{
		RawDefaultDNSRule: option.RawDefaultDNSRule{
			Domain: []string{
				"1.0.0.127.in-addr.arpa",
				"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
			},
		},
		DNSRuleAction: option.DNSRuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.DNSRouteActionOptions{
				Server:         DNSLocalTag,
				BypassIfFailed: false,
			},
		},
	})
}

var defaultDirectDomainSuffixRules = []string{
	"work.weixin.qq.com",
	"weixin.qq.com",
	"weixinbridge.com",
	"wxwork.qq.com",
	"wecom.qq.com",
	"qq.com",
	"qpic.cn",
	"qpic.com",
	"gtimg.cn",
	"gtimg.com",
	"myqcloud.com",
	"qcloud.com",
	"huaweicloud.com",
	"myhuaweicloud.com",
	"huaweicloudapis.com",
	"huaweicloudwaf.com",
	"huaweicloud.ru",
	"huawei.com",
	"hicloud.com",
	"vmall.com",
	"hc-cdn.com",
	"hc-cdn.cn",
	"cdnhwc1.com",
	"cdnhwc2.com",
	"dbankcloud.cn",
	"dbankcloud.com",
	"dbankcloud.asia",
	"dbankcloud.eu",
	"globalsign.com",
	"globalsigncdn.com",
}

func appendDirectDomainSuffixRules(
	dnsRules []option.DefaultDNSRule,
	routeRules []option.Rule,
	hopt *HiddifyOptions,
	domainSuffixes []string,
) ([]option.DefaultDNSRule, []option.Rule) {
	if len(domainSuffixes) == 0 {
		return dnsRules, routeRules
	}
	dnsRules = appendDirectDNSRules(
		dnsRules,
		option.RawDefaultDNSRule{
			DomainSuffix: domainSuffixes,
		},
		hopt,
	)
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				DomainSuffix: domainSuffixes,
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: OutboundDirectTag,
				},
			},
		},
	})
	return dnsRules, routeRules
}

func setInbound(options *option.Options, hopt *HiddifyOptions) {
	// var inboundDomainStrategy option.DomainStrategy
	// if !opt.ResolveDestination {
	// 	inboundDomainStrategy = option.DomainStrategy(dns.DomainStrategyAsIS)
	// } else {
	// 	inboundDomainStrategy = opt.IPv6Mode
	// }
	ipv6Enable := shouldEnableIPv6(hopt)
	if hopt.EnableTun {

		opts := option.TunInboundOptions{
			Stack:       hopt.TUNStack,
			MTU:         hopt.MTU,
			AutoRoute:   true,
			StrictRoute: hopt.StrictRoute,

			// EndpointIndependentNat: true,
			// GSO:                    runtime.GOOS != "windows",

		}
		tunInbound := option.Inbound{
			Type: C.TypeTun,
			Tag:  InboundTUNTag,

			Options: &opts,
		}
		// switch hopt.IPv6Mode {
		// case option.DomainStrategy(dns.DomainStrategyUseIPv4):
		// 	opts.Address = []netip.Prefix{
		// 		netip.MustParsePrefix("172.19.0.1/28"),
		// 	}
		// case option.DomainStrategy(dns.DomainStrategyUseIPv6):
		// 	opts.Address = []netip.Prefix{
		// 		netip.MustParsePrefix("fdfe:dcba:9876::1/126"),
		// 	}
		// default:

		// }
		opts.Address = []netip.Prefix{netip.MustParsePrefix("172.19.0.1/28")}
		if ipv6Enable {
			opts.Address = append(opts.Address, netip.MustParsePrefix("fdfe:dcba:9876::1/126"))
		}

		options.Inbounds = append(options.Inbounds, tunInbound)

	}

	binds := []string{}

	if hopt.AllowConnectionFromLAN {
		if ipv6Enable {
			binds = append(binds, "::")
		} else {
			binds = append(binds, "0.0.0.0")
		}
	} else {
		if ipv6Enable {
			binds = append(binds, "::1")
		}
		binds = append(binds, "127.0.0.1")
	}

	for _, bind := range binds {
		addr := badoption.Addr(netip.MustParseAddr(bind))

		options.Inbounds = append(
			options.Inbounds,
			option.Inbound{
				Type: C.TypeMixed,
				Tag:  InboundMixedTag + bind,
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     &addr,
						ListenPort: hopt.MixedPort,
						// InboundOptions: option.InboundOptions{
						// 	SniffEnabled:             true,
						// 	SniffOverrideDestination: true,
						// 	DomainStrategy:           inboundDomainStrategy,
						// },
					},
					SetSystemProxy: hopt.SetSystemProxy,
				},
			},
		)
		if C.IsLinux && !C.IsAndroid && hopt.TProxyPort > 0 && hutils.IsAdmin() {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeTProxy,
					Tag:  InboundTProxy + bind,
					Options: &option.TProxyInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.TProxyPort,
						},
					},
				},
			)
		}
		if (C.IsLinux || C.IsDarwin) && !C.IsAndroid && hopt.RedirectPort > 0 {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeRedirect,
					Tag:  InboundRedirect + bind,
					Options: &option.RedirectInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.RedirectPort,
						},
					},
				},
			)
		}
		if hopt.DirectPort > 0 {
			options.Inbounds = append(
				options.Inbounds,
				option.Inbound{
					Type: C.TypeDirect,
					Tag:  InboundDirectTag + bind,
					Options: &option.DirectInboundOptions{
						ListenOptions: option.ListenOptions{
							Listen:     &addr,
							ListenPort: hopt.DirectPort,
						},
					},
				},
			)
		}
	}
}

func setRoutingOptions(options *option.Options, hopt *HiddifyOptions) error {
	dnsRules := []option.DefaultDNSRule{}
	routeRules := []option.Rule{}
	rulesets := []option.RuleSet{}

	// if opt.EnableTun && runtime.GOOS == "android" {
	// 	// routeRules = append(
	// 	// 	routeRules,
	// 	// 	option.Rule{
	// 	// 		Type: C.RuleTypeDefault,

	// 	// 		DefaultOptions: option.DefaultRule{
	// 	// 			Inbound:     []string{InboundTUNTag},
	// 	// 			PackageName: []string{"app.hiddify.com"},
	// 	// 			Outbound:    OutboundBypassTag,
	// 	// 		},
	// 	// 	},
	// 	// )
	// }
	// if opt.EnableTun && runtime.GOOS == "windows" {
	// 	// routeRules = append(
	// 	// 	routeRules,
	// 	// 	option.Rule{
	// 	// 		Type: C.RuleTypeDefault,
	// 	// 		DefaultOptions: option.DefaultRule{
	// 	// 			ProcessName: []string{"Hiddify", "Hiddify.exe", "HiddifyCli", "HiddifyCli.exe"},
	// 	// 			Outbound:    OutboundBypassTag,
	// 	// 		},
	// 	// 	},
	// 	// )
	// }

	// dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server:         DNSStaticTag,
	// 			BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )
	forceDirectRules, err := addForceDirect(options, hopt)
	if err != nil {
		return err
	}

	dnsRules = append(dnsRules, forceDirectRules...)
	dnsRules = appendLocalReverseDNSRules(dnsRules)

	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeSniff,
			},
		},
	})
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				Protocol: []string{C.ProtocolDNS},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeHijackDNS,
			},
		},
	})
	if hopt.IPv6Mode == option.DomainStrategy(C.DomainStrategyIPv4Only) {
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					IPVersion: 6,
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeReject,
					RejectOptions: option.RejectActionOptions{
						Method: C.RuleActionRejectMethodDefault,
					},
				},
			},
		})
	}

	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,

		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				IPCIDR: []string{
					"10.10.34.0/24",
					"2001:4188:2:600:10:10:34:0/120",
				},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: OutboundMainDetour,
				},
			},
		},
	})
	// {
	// 	Type: C.RuleTypeDefault,
	// 	DefaultOptions: option.DefaultRule{
	// 		ClashMode: "Direct",
	// 		Outbound:  OutboundDirectTag,
	// 	},
	// },
	// {
	// 	Type: C.RuleTypeDefault,
	// 	DefaultOptions: option.DefaultRule{
	// 		ClashMode: "Global",
	// 		Outbound:  OutboundMainProxyTag,
	// 	},
	// },	}

	if hopt.BypassLAN {
		routeRules = append(
			routeRules,
			option.Rule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultRule{
					RawDefaultRule: option.RawDefaultRule{
						IPIsPrivate: true,
					},
					RuleAction: option.RuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.RouteActionOptions{
							Outbound: OutboundDirectTag,
						},
					},
				},
			},
		)
	}

	dynamicDirectBypassMatchers := loadDynamicDirectBypassRouteMatchers(hopt, time.Now())
	routeRules = appendDynamicDirectBypassCIDRRouteRules(routeRules, dynamicDirectBypassMatchers)
	routeRules = appendTunSniffOverrideDestinationRule(routeRules, hopt)
	routeRules = appendDynamicDirectBypassDomainRouteRules(routeRules, dynamicDirectBypassMatchers)

	// for _, rule := range opt.Rules {
	// 	routeRule := rule.MakeRule()
	// 	switch rule.Outbound {
	// 	case "bypass":
	// 		routeRule.Outbound = OutboundBypassTag
	// 	case "block":
	// 		routeRule.Outbound = OutboundBlockTag
	// 	case "proxy":
	// 		routeRule.Outbound = OutboundMainProxyTag
	// 	}

	// 	if routeRule.IsValid() {
	// 		routeRules = append(
	// 			routeRules,
	// 			option.Rule{
	// 				Type:           C.RuleTypeDefault,
	// 				DefaultOptions: routeRule,
	// 			},
	// 		)
	// 	}

	// 	dnsRule := rule.MakeDNSRule()
	// 	switch rule.Outbound {
	// 	case "bypass":
	// 		dnsRule.Server = DNSDirectTag
	// 	case "block":
	// 		dnsRule.Server = DNSBlockTag
	// 		dnsRule.DisableCache = true
	// 	case "proxy":
	// 		if opt.EnableFakeDNS {
	// 			fakeDnsRule := dnsRule
	// 			fakeDnsRule.Server = DNSFakeTag
	// 			fakeDnsRule.Inbound = []string{InboundTUNTag, InboundMixedTag}
	// 			dnsRules = append(dnsRules, fakeDnsRule)
	// 		}
	// 		dnsRule.Server = DNSRemoteTag
	// 	}
	// 	dnsRules = append(dnsRules, dnsRule)
	// }
	forceDirectRoute := make([]string, 0)
	if options.NTP != nil && options.NTP.Enabled {
		forceDirectRoute = append(forceDirectRoute, options.NTP.Server)
	}

	// parsedURL, err := url.Parse(opt.ConnectionTestUrl)
	// if err == nil {
	// 	dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 		Domain:       []string{parsedURL.Host},
	// 		Server:       DNSRemoteTag,
	// 		RewriteTTL:   &dnsCPttl,
	// 		DisableCache: false,
	// 	})
	// }

	if len(forceDirectRoute) > 0 {

		dnsRules = appendDirectDNSRules(
			dnsRules,
			option.RawDefaultDNSRule{
				Domain: forceDirectRoute,
			},
			hopt,
		)
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Domain: forceDirectRoute,
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{
						Outbound: OutboundDirectTag,
					},
				},
			},
		})
	}
	dnsRules, routeRules = appendDirectDomainSuffixRules(
		dnsRules,
		routeRules,
		hopt,
		configuredDirectDomainSuffixRules(hopt),
	)
	rejectRCode := (option.DNSRCode(sdns.RcodeRefused))
	rejectDnsAction := option.DNSRuleAction{
		Action: C.RuleActionTypePredefined,
		PredefinedOptions: option.DNSRouteActionPredefined{
			Rcode: &rejectRCode,
		},
	}
	if hopt.BlockAds {
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geosite-ads",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-category-ads-all.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geosite-malware",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-malware.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geosite-phishing",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-phishing.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geosite-cryptominers",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geosite-cryptominers.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geoip-phishing",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geoip-phishing.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})
		rulesets = append(rulesets, option.RuleSet{
			Type:   C.RuleSetTypeRemote,
			Tag:    "geoip-malware",
			Format: C.RuleSetFormatBinary,
			RemoteOptions: option.RemoteRuleSet{
				URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/block/geoip-malware.srs",
				UpdateInterval: badoption.Duration(5 * time.Hour * 24),
				DownloadDetour: OutboundSelectTag,
			},
		})

		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					RuleSet: []string{
						"geosite-ads",
						"geosite-malware",
						"geosite-phishing",
						"geosite-cryptominers",
						"geoip-malware",
						"geoip-phishing",
					},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeReject,
					RejectOptions: option.RejectActionOptions{
						Method: C.RuleActionRejectMethodDefault,
					},
				},
			},
		})
		dnsRules = append(dnsRules, option.DefaultDNSRule{
			RawDefaultDNSRule: option.RawDefaultDNSRule{

				RuleSet: []string{
					"geosite-ads",
					"geosite-malware",
					"geosite-phishing",
					"geosite-cryptominers",
				},
			},
			DNSRuleAction: rejectDnsAction,
		})
	}
	if hopt.Region != "other" {
		dnsRules = appendDirectDNSRules(
			dnsRules,
			option.RawDefaultDNSRule{
				DomainSuffix: []string{"." + hopt.Region},
			},
			hopt,
		)
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					DomainSuffix: []string{"." + hopt.Region},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{
						Outbound: OutboundDirectTag,
					},
				},
			},
		})

		dnsRules = appendDirectDNSRules(
			dnsRules,
			option.RawDefaultDNSRule{
				RuleSet: []string{
					"geosite-" + hopt.Region,
				},
			},
			hopt,
		)

		regionRouteSets := []string{"geosite-" + hopt.Region}
		if !hopt.EnableTun && !hopt.EnableTunService {
			regionRouteSets = append([]string{"geoip-" + hopt.Region}, regionRouteSets...)
			rulesets = append(rulesets, makeCountryRuleSet("geoip-"+hopt.Region, hopt))
		}
		rulesets = append(rulesets, makeCountryRuleSet("geosite-"+hopt.Region, hopt))

		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					RuleSet: regionRouteSets,
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{
						Outbound: OutboundDirectTag,
					},
				},
			},
		})
	}
	if hopt.RouteOptions.BlockQuic {
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Protocol: []string{C.ProtocolQUIC},
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeReject,
					RejectOptions: option.RejectActionOptions{
						Method: C.RuleActionRejectMethodDefault,
					},
				},
			},
		})
	}
	options.Route = &option.RouteOptions{
		Rules:               routeRules,
		Final:               OutboundMainDetour,
		AutoDetectInterface: (!C.IsAndroid && !C.IsIos) && (hopt.EnableTun || hopt.EnableTunService),
		DefaultDomainResolver: &option.DomainResolveOptions{
			Server:   defaultDomainResolverServer(hopt),
			Strategy: effectiveDirectDNSDomainStrategy(hopt),
		},
		// OverrideAndroidVPN: hopt.EnableTun && C.IsAndroid,
		RuleSet:     rulesets,
		FindProcess: C.IsWindows && (hopt.EnableTun || hopt.EnableTunService) && hopt.EnableDynamicDirectBypass,
		// GeoIP: &option.GeoIPOptions{
		// 	Path: opt.GeoIPPath,
		// },
		// Geosite: &option.GeositeOptions{
		// 	Path: opt.GeoSitePath,
		// },
	}
	// if opt.EnableDNSRouting {
	if hopt.EnableFakeDNS {
		// inbounds := []string{InboundTUNTag}
		// for _, inp := range options.Inbounds {
		// 	if strings.Contains(inp.Tag, InboundDirectTag) || strings.Contains(inp.Tag, InboundRedirect) || strings.Contains(inp.Tag, InboundTProxy) {
		// 		inbounds = append(inbounds, inp.Tag)
		// 	}
		// }
		dnsRules = append(
			dnsRules,
			option.DefaultDNSRule{
				RawDefaultDNSRule: option.RawDefaultDNSRule{
					// Inbound: inbounds,
					QueryType: badoption.Listable[option.DNSQueryType]{
						option.DNSQueryType(mDNS.StringToType["A"]),
						option.DNSQueryType(mDNS.StringToType["AAAA"]),
					},
				},
				DNSRuleAction: option.DNSRuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.DNSRouteActionOptions{
						Server:         DNSFakeTag,
						Strategy:       effectiveRemoteDNSDomainStrategy(hopt),
						RewriteTTL:     &DEFAULT_DNS_TTL,
						DisableCache:   true,
						BypassIfFailed: false,
					},
				},
			})

	}

	dnsRules = append(dnsRules, option.DefaultDNSRule{
		RawDefaultDNSRule: option.RawDefaultDNSRule{},
		DNSRuleAction: option.DNSRuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.DNSRouteActionOptions{
				Server:         DNSMultiRemoteTag,
				Strategy:       effectiveRemoteDNSDomainStrategy(hopt),
				RewriteTTL:     &DEFAULT_DNS_TTL,
				BypassIfFailed: false,
			},
		},
	},
	)
	// dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server:         DNSRemoteTagFallback,
	// 			Strategy:       hopt.RemoteDnsDomainStrategy,
	// 			RewriteTTL:     &DEFAULT_DNS_TTL,
	// 			BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )

	// dnsRules = append(dnsRules, option.DefaultDNSRule{

	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server:         DNSTricksDirectTag,
	// 			BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )
	// dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server:         DNSDirectTag,
	// 			BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )
	// dnsRules = append(dnsRules, option.DefaultDNSRule{
	// 	RawDefaultDNSRule: option.RawDefaultDNSRule{},
	// 	DNSRuleAction: option.DNSRuleAction{
	// 		Action: C.RuleActionTypeRoute,
	// 		RouteOptions: option.DNSRouteActionOptions{
	// 			Server: DNSLocalTag,
	// 			// BypassIfFailed: false,
	// 		},
	// 	},
	// },
	// )

	for _, dnsRule := range dnsRules {
		if dnsRule.IsValid() {
			options.DNS.Rules = append(
				options.DNS.Rules,
				option.DNSRule{
					Type:           C.RuleTypeDefault,
					DefaultOptions: dnsRule,
				},
			)
		}
	}
	// }
	return nil
}

func makeCountryRuleSet(tag string, hopt *HiddifyOptions) option.RuleSet {
	if filePath, configPath := localCountryRuleSetPaths(tag, hopt); filePath != "" && localRuleSetFileExists(filePath) {
		return option.RuleSet{
			Type:   C.RuleSetTypeLocal,
			Tag:    tag,
			Format: C.RuleSetFormatBinary,
			LocalOptions: option.LocalRuleSet{
				Path: configPath,
			},
		}
	}
	return option.RuleSet{
		Type:   C.RuleSetTypeRemote,
		Tag:    tag,
		Format: C.RuleSetFormatBinary,
		RemoteOptions: option.RemoteRuleSet{
			URL:            "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/country/" + tag + ".srs",
			UpdateInterval: badoption.Duration(5 * time.Hour * 24),
			DownloadDetour: OutboundSelectTag,
		},
	}
}

func localCountryRuleSetPaths(tag string, hopt *HiddifyOptions) (string, string) {
	if hopt == nil || hopt.DirectDomainSuffixRulesPath == "" {
		return "", ""
	}
	filePath := filepath.Clean(filepath.Join(filepath.Dir(hopt.DirectDomainSuffixRulesPath), tag+".srs"))
	configPath := filepath.ToSlash(filepath.Join(RulesRelativeDir, tag+".srs"))
	return filePath, configPath
}

func localRuleSetFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}

type dynamicDirectBypassRouteCacheEntry struct {
	Host        string    `json:"host"`
	IP          string    `json:"ip"`
	ProcessName string    `json:"process_name,omitempty"`
	ProcessPath string    `json:"process_path,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func appendDynamicDirectBypassDomainRouteRules(routeRules []option.Rule, matchers dynamicDirectBypassRouteMatchers) []option.Rule {
	if len(matchers.domains) == 0 && len(matchers.cidrs) == 0 {
		return routeRules
	}
	if len(matchers.domains) > 0 {
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					Domain: matchers.domains,
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{
						Outbound: OutboundDirectTag,
					},
				},
			},
		})
	}
	return routeRules
}

func appendDynamicDirectBypassCIDRRouteRules(routeRules []option.Rule, matchers dynamicDirectBypassRouteMatchers) []option.Rule {
	if len(matchers.cidrs) > 0 {
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{
					IPCIDR: matchers.cidrs,
				},
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{
						Outbound: OutboundDirectTag,
					},
				},
			},
		})
	}
	return routeRules
}

func appendTunSniffOverrideDestinationRule(routeRules []option.Rule, hopt *HiddifyOptions) []option.Rule {
	if hopt == nil || (!hopt.EnableTun && !hopt.EnableTunService) {
		return routeRules
	}
	return append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				Inbound: []string{InboundTUNTag},
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeSniff,
				SniffOptions: option.RouteActionSniff{
					OverrideDestination: true,
				},
			},
		},
	})
}

type dynamicDirectBypassRouteMatchers struct {
	domains []string
	cidrs   []string
}

func loadDynamicDirectBypassRouteMatchers(hopt *HiddifyOptions, now time.Time) dynamicDirectBypassRouteMatchers {
	if hopt == nil || !hopt.EnableDynamicDirectBypass || hopt.DynamicDirectBypassRoutesPath == "" {
		return dynamicDirectBypassRouteMatchers{}
	}
	data, err := os.ReadFile(hopt.DynamicDirectBypassRoutesPath)
	if err != nil {
		return dynamicDirectBypassRouteMatchers{}
	}
	var entries []dynamicDirectBypassRouteCacheEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return dynamicDirectBypassRouteMatchers{}
	}
	maxRoutes := hopt.DynamicDirectBypassMaxRoutes
	if maxRoutes <= 0 {
		maxRoutes = DefaultDynamicDirectBypassMaxRoutes
	}
	maxRoutesPerHost := hopt.DynamicDirectBypassMaxRoutesHost
	if maxRoutesPerHost <= 0 {
		maxRoutesPerHost = DefaultDynamicDirectBypassMaxRoutesHost
	}
	hostCounts := map[string]int{}
	seenCIDRs := map[string]struct{}{}
	seenDomains := map[string]struct{}{}
	domains := make([]string, 0, len(entries))
	cidrs := make([]string, 0, len(entries))
	for _, entry := range entries {
		if len(cidrs) >= maxRoutes {
			break
		}
		if isDynamicDirectBypassConfigSelfRoute(entry) {
			continue
		}
		if !entry.ExpiresAt.IsZero() && !now.Before(entry.ExpiresAt) {
			continue
		}
		addr, err := netip.ParseAddr(entry.IP)
		if err != nil || !isDynamicDirectBypassConfigRouteIP(addr) {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(entry.Host))
		if host != "" {
			if hostCounts[host] >= maxRoutesPerHost {
				continue
			}
			hostCounts[host]++
		}
		if isDynamicDirectBypassConfigRouteHost(host) {
			if _, exists := seenDomains[host]; !exists {
				seenDomains[host] = struct{}{}
				domains = append(domains, host)
			}
		}
		cidr := addr.String() + "/32"
		if _, exists := seenCIDRs[cidr]; exists {
			continue
		}
		seenCIDRs[cidr] = struct{}{}
		cidrs = append(cidrs, cidr)
	}
	sort.Strings(domains)
	sort.Strings(cidrs)
	return dynamicDirectBypassRouteMatchers{
		domains: domains,
		cidrs:   cidrs,
	}
}

func isDynamicDirectBypassConfigRouteIP(addr netip.Addr) bool {
	return addr.IsValid() &&
		addr.Is4() &&
		addr.IsGlobalUnicast() &&
		!addr.IsPrivate() &&
		!addr.IsLoopback() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsMulticast() &&
		!addr.IsUnspecified()
}

func isDynamicDirectBypassConfigRouteHost(host string) bool {
	if host == "" || strings.ContainsAny(host, " \t\r\n/") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	return true
}

func isDynamicDirectBypassConfigSelfRoute(entry dynamicDirectBypassRouteCacheEntry) bool {
	processName := strings.ToLower(strings.TrimSpace(entry.ProcessName))
	if processName == "" {
		processPath := strings.TrimSpace(entry.ProcessPath)
		index := strings.LastIndexAny(processPath, `\/`)
		if index >= 0 && index+1 < len(processPath) {
			processName = strings.ToLower(processPath[index+1:])
		} else {
			processName = strings.ToLower(processPath)
		}
	}
	return processName == "hiddify.exe" || processName == "hiddify"
}

func patchHiddifyWarpFromConfig(out *option.Outbound, opt HiddifyOptions) *option.Outbound {
	if out.Type == C.TypePsiphon {
		return out
	}
	if opt.Warp.EnableWarp && opt.Warp.Mode == "proxy_over_warp" {
		if opts, ok := out.Options.(option.DialerOptionsWrapper); ok {
			dialer := opts.TakeDialerOptions()
			dialer.Detour = WARPConfigTag
			opts.ReplaceDialerOptions(dialer)
		}
	}
	return out
}

var (
	ipMaps      = map[string][]string{}
	ipMapsMutex sync.Mutex
)

func getIPs(domains ...string) []string {
	var wg sync.WaitGroup
	resChan := make(chan string, len(domains)*10) // Collect both IPv4 and IPv6
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	for _, d := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
			if err != nil {
				return
			}
			for _, ip := range ips {
				ipStr := ip.String()
				if !isBlockedIP(ipStr) {
					resChan <- ipStr
				}
			}
		}(d)
	}

	go func() {
		wg.Wait()
		close(resChan)
	}()

	var res []string
	for ip := range resChan {
		res = append(res, ip)
	}
	if len(res) == 0 && ipMaps[domains[0]] != nil {
		return ipMaps[domains[0]]
	}
	ipMapsMutex.Lock()
	ipMaps[domains[0]] = res
	ipMapsMutex.Unlock()

	return res
}

func isBlockedDomain(domain string) bool {
	if strings.HasPrefix("full:", domain) {
		return false
	}
	if strings.Contains(domain, "instagram") || strings.Contains(domain, "facebook") || strings.Contains(domain, "telegram") || strings.Contains(domain, "t.me") {
		return true
	}
	ips := getIPs(domain)
	if len(ips) == 0 {
		// fmt.Println(err)
		return true
	}

	// // Print the IP addresses associated with the domain
	// fmt.Printf("IP addresses for %s:\n", domain)
	// for _, ip := range ips {
	// 	if isBlockedIP(ip) {
	// 		return true
	// 	}
	// }
	return false
}

func isBlockedIP(ip string) bool {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "2001:4188:2:600:10") {
		return true
	}
	return false
}

func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func generateRandomString(length int) string {
	// Determine the number of bytes needed
	bytesNeeded := (length*6 + 7) / 8

	// Generate random bytes
	randomBytes := make([]byte, bytesNeeded)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "hiddify"
	}

	// Encode random bytes to base64
	randomString := base64.URLEncoding.EncodeToString(randomBytes)

	// Trim padding characters and return the string
	return randomString[:length]
}
