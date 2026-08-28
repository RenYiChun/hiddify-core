package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestSetExperimentalPrefersReliableHTTPSConnectionTestURLs(t *testing.T) {
	var options option.Options
	hopt := &HiddifyOptions{
		EnableClashApi: true,
		ClashApiPort:   16756,
		URLTestOptions: URLTestOptions{
			ConnectionTestUrl: "http://captive.apple.com/hotspot-detect.html",
			URLTestInterval:   DurationInSeconds(60),
		},
	}

	setExperimental(&options, hopt)

	if options.Experimental == nil || options.Experimental.Monitoring == nil {
		t.Fatal("expected monitoring options to be generated")
	}
	urls := options.Experimental.Monitoring.URLs
	if len(urls) == 0 {
		t.Fatal("expected monitoring URLs")
	}
	if urls[0] == "http://captive.apple.com/hotspot-detect.html" {
		t.Fatalf("expected a reliable HTTPS URL before the configured Apple captive URL, got %#v", urls)
	}
	if !containsString(urls, "http://captive.apple.com/hotspot-detect.html") {
		t.Fatalf("expected configured URL to be preserved as a fallback, got %#v", urls)
	}
	if options.Experimental.Monitoring.Workers != 3 {
		t.Fatalf("expected monitoring workers to be capped at 3, got %d", options.Experimental.Monitoring.Workers)
	}
	if got := options.Experimental.Monitoring.URLTestLogFile; got != "data/url-test.log" {
		t.Fatalf("expected URL test log file %q, got %q", "data/url-test.log", got)
	}
}

func TestSetLogEnablesWallClockTimestampsForBoxLog(t *testing.T) {
	var options option.Options
	hopt := DefaultHiddifyOptions()

	setLog(&options, hopt)

	if options.Log == nil {
		t.Fatal("expected log options")
	}
	if options.Log.Output != "data/box.log" {
		t.Fatalf("expected box log output, got %q", options.Log.Output)
	}
	if !options.Log.Timestamp {
		t.Fatal("expected box.log to include wall-clock timestamps")
	}
}

func TestSetHiddifyCustomOptionsAddsRouteAdmissionLimits(t *testing.T) {
	options := option.Options{}
	hopt := &HiddifyOptions{
		RouteOptions: RouteOptions{
			DirectRouteConnectionLimit: 768,
			ProxyRouteConnectionLimit:  192,
		},
	}

	setHiddifyCustomOptions(&options, hopt)

	if options.Custom == nil {
		t.Fatal("expected custom options")
	}
	if got := (*options.Custom)[customRouteDirectConnectionLimitKey]; got != 768 {
		t.Fatalf("expected direct route connection limit 768, got %#v", got)
	}
	if got := (*options.Custom)[customRouteProxyConnectionLimitKey]; got != 192 {
		t.Fatalf("expected proxy route connection limit 192, got %#v", got)
	}
}

func TestSetHiddifyCustomOptionsAddsProcessStableProxyDiagnostics(t *testing.T) {
	options := option.Options{
		Outbounds: []option.Outbound{
			{
				Type: C.TypeBalancer,
				Tag:  OutboundProcessStableProxyTag,
				Options: &option.BalancerOutboundOptions{
					Outbounds: []string{
						"209.87.93.20 tls httpupgrade direct vless § 443 1",
						"209.87.93.20 tls grpc direct vmess § 443 1",
					},
				},
			},
			{
				Type: C.TypeVLESS,
				Tag:  "209.87.93.20 tls httpupgrade direct vless § 443 1",
			},
			{
				Type: C.TypeNaive,
				Tag:  "209.87.93.20 NaiveTLS § 443 1",
			},
			{
				Type: C.TypeVLESS,
				Tag:  "209.87.93.20 h3_quic xhttp direct vless § 443 1",
			},
			{
				Type: C.TypeVMess,
				Tag:  "209.87.93.20 tls grpc direct vmess § 443 1",
			},
		},
	}
	hopt := &HiddifyOptions{
		RouteOptions: RouteOptions{
			EnableProcessStableProxyRules:      true,
			ProcessStableProxyRuleNames:        []string{"codex.exe", "Codex.exe"},
			ProcessStableProxyExcludedKeywords: []string{"naive", "quic"},
		},
	}

	setHiddifyCustomOptions(&options, hopt)

	if options.Custom == nil {
		t.Fatal("expected custom options")
	}
	custom := *options.Custom
	if got := custom[customProcessStableProxyEnabledKey]; got != true {
		t.Fatalf("expected process stable proxy enabled diagnostic, got %#v", got)
	}
	if got := custom[customProcessStableProxyRuleNamesKey]; !stringSlicesEqual(got.([]string), []string{"codex.exe", "Codex.exe"}) {
		t.Fatalf("expected process stable proxy rule names diagnostic, got %#v", got)
	}
	if got := custom[customProcessStableProxyCandidateOutboundsKey]; !stringSlicesEqual(got.([]string), []string{
		"209.87.93.20 tls httpupgrade direct vless § 443 1",
		"209.87.93.20 tls grpc direct vmess § 443 1",
	}) {
		t.Fatalf("expected process stable proxy candidate outbounds diagnostic, got %#v", got)
	}
	if got := custom[customProcessStableProxyExcludedOutboundsKey]; !stringSlicesEqual(got.([]string), []string{
		"209.87.93.20 NaiveTLS § 443 1",
		"209.87.93.20 h3_quic xhttp direct vless § 443 1",
	}) {
		t.Fatalf("expected process stable proxy excluded outbounds diagnostic, got %#v", got)
	}
	if got := custom["hiddify-process-stable-proxy-fallback"]; got != false {
		t.Fatalf("expected process stable proxy fallback diagnostic to be false, got %#v", got)
	}
	if got := custom["hiddify-process-stable-proxy-fallback-reason"]; got != "" {
		t.Fatalf("expected empty process stable proxy fallback reason, got %#v", got)
	}
}

func TestSetHiddifyCustomOptionsReportsProcessStableProxyFallback(t *testing.T) {
	options := option.Options{
		Outbounds: []option.Outbound{
			{
				Type: C.TypeBalancer,
				Tag:  OutboundProcessStableProxyTag,
				Options: &option.BalancerOutboundOptions{
					Outbounds: []string{
						"209.87.93.20 NaiveTLS § 443 1",
						"209.87.93.20 h3_quic xhttp direct vless § 443 1",
					},
				},
			},
			{
				Type: C.TypeNaive,
				Tag:  "209.87.93.20 NaiveTLS § 443 1",
			},
			{
				Type: C.TypeVLESS,
				Tag:  "209.87.93.20 h3_quic xhttp direct vless § 443 1",
			},
		},
	}
	hopt := &HiddifyOptions{
		RouteOptions: RouteOptions{
			EnableProcessStableProxyRules: true,
			ProcessStableProxyRuleNames:   []string{"codex.exe"},
		},
	}

	setHiddifyCustomOptions(&options, hopt)

	if options.Custom == nil {
		t.Fatal("expected custom options")
	}
	custom := *options.Custom
	if got := custom["hiddify-process-stable-proxy-fallback"]; got != true {
		t.Fatalf("expected process stable proxy fallback diagnostic to be true, got %#v", got)
	}
	if got := custom["hiddify-process-stable-proxy-fallback-reason"]; got != "no stable candidates after excluded keywords" {
		t.Fatalf("expected process stable proxy fallback reason, got %#v", got)
	}
	if got := custom[customProcessStableProxyExcludedOutboundsKey]; !stringSlicesEqual(got.([]string), []string{
		"209.87.93.20 NaiveTLS § 443 1",
		"209.87.93.20 h3_quic xhttp direct vless § 443 1",
	}) {
		t.Fatalf("expected fallback diagnostics to keep excluded outbounds, got %#v", got)
	}
}

func TestSetHiddifyCustomOptionsDoesNotReportProcessStableProxyOutboundsWhenInactive(t *testing.T) {
	options := option.Options{
		Outbounds: []option.Outbound{
			{
				Type: C.TypeNaive,
				Tag:  "209.87.93.20 NaiveTLS § 443 1",
			},
		},
	}

	setHiddifyCustomOptions(&options, &HiddifyOptions{})

	if options.Custom == nil {
		t.Fatal("expected custom options")
	}
	custom := *options.Custom
	if got := custom[customProcessStableProxyEnabledKey]; got != false {
		t.Fatalf("expected process stable proxy disabled diagnostic, got %#v", got)
	}
	if got := custom[customProcessStableProxyCandidateOutboundsKey]; len(got.([]string)) != 0 {
		t.Fatalf("expected no candidate outbounds when inactive, got %#v", got)
	}
	if got := custom[customProcessStableProxyExcludedOutboundsKey]; len(got.([]string)) != 0 {
		t.Fatalf("expected no excluded outbounds when inactive, got %#v", got)
	}
}

func TestSetHiddifyCustomOptionsDefaultsInvalidRouteAdmissionLimits(t *testing.T) {
	options := option.Options{}

	setHiddifyCustomOptions(&options, &HiddifyOptions{})

	if options.Custom == nil {
		t.Fatal("expected custom options")
	}
	if got := (*options.Custom)[customRouteDirectConnectionLimitKey]; got != DefaultDirectRouteConnectionLimit {
		t.Fatalf("expected default direct route connection limit %d, got %#v", DefaultDirectRouteConnectionLimit, got)
	}
	if got := (*options.Custom)[customRouteProxyConnectionLimitKey]; got != DefaultProxyRouteConnectionLimit {
		t.Fatalf("expected default proxy route connection limit %d, got %#v", DefaultProxyRouteConnectionLimit, got)
	}
}

func TestSetHiddifyCustomOptionsNormalizesLegacyRouteAdmissionDefaults(t *testing.T) {
	options := option.Options{}
	hopt := &HiddifyOptions{
		RouteOptions: RouteOptions{
			DirectRouteConnectionLimit: 512,
			ProxyRouteConnectionLimit:  256,
		},
	}

	setHiddifyCustomOptions(&options, hopt)

	if options.Custom == nil {
		t.Fatal("expected custom options")
	}
	if got := (*options.Custom)[customRouteDirectConnectionLimitKey]; got != DefaultDirectRouteConnectionLimit {
		t.Fatalf("expected legacy direct route limit to normalize to %d, got %#v", DefaultDirectRouteConnectionLimit, got)
	}
	if got := (*options.Custom)[customRouteProxyConnectionLimitKey]; got != DefaultProxyRouteConnectionLimit {
		t.Fatalf("expected legacy proxy route limit to normalize to %d, got %#v", DefaultProxyRouteConnectionLimit, got)
	}
}

func TestSetHiddifyCustomOptionsAddsDynamicDirectBypassOptions(t *testing.T) {
	options := option.Options{}
	hopt := &HiddifyOptions{
		RouteOptions: RouteOptions{
			EnableDynamicDirectBypass:        true,
			DynamicDirectBypassTTL:           DurationInSeconds(900),
			DynamicDirectBypassMaxRoutes:     128,
			DynamicDirectBypassMaxRoutesHost: 16,
		},
	}

	setHiddifyCustomOptions(&options, hopt)

	if options.Custom == nil {
		t.Fatal("expected custom options")
	}
	custom := *options.Custom
	if got := custom[customDynamicDirectBypassEnabledKey]; got != true {
		t.Fatalf("expected dynamic direct bypass enabled, got %#v", got)
	}
	if got := custom[customDynamicDirectBypassTTLKey]; got != 900 {
		t.Fatalf("expected ttl 900, got %#v", got)
	}
	if got := custom[customDynamicDirectBypassMaxRoutesKey]; got != 128 {
		t.Fatalf("expected max routes 128, got %#v", got)
	}
	if got := custom[customDynamicDirectBypassMaxRoutesHostKey]; got != 16 {
		t.Fatalf("expected max routes per host 16, got %#v", got)
	}
	suffixes, ok := custom[customDynamicDirectBypassEagerSuffixesKey].([]string)
	if !ok {
		t.Fatalf("expected eager suffixes to be []string, got %#v", custom[customDynamicDirectBypassEagerSuffixesKey])
	}
	if !containsString(suffixes, "myqcloud.com") ||
		!containsString(suffixes, "tencentcloudapi.com") ||
		!containsString(suffixes, "tcloudbase.com") ||
		!containsString(suffixes, "weixinbridge.com") ||
		!containsString(suffixes, "servicewechat.com") ||
		!containsString(suffixes, "weapp.tencentcloudapi.com") ||
		!containsString(suffixes, "wxqcloud.qq.com.cn") {
		t.Fatalf("expected eager suffixes to include WeCom and WeChat DevTools domains, got %#v", suffixes)
	}
}

func TestDefaultHiddifyOptionsBypassLANEnabled(t *testing.T) {
	hopt := DefaultHiddifyOptions()

	if !hopt.BypassLAN {
		t.Fatal("expected bypass LAN to be enabled by default")
	}
}

func TestSetRoutingOptionsEnablesFindProcessForWindowsDynamicBypassTun(t *testing.T) {
	options := option.Options{DNS: &option.DNSOptions{}}
	hopt := DefaultHiddifyOptions()
	hopt.EnableTun = true
	hopt.EnableDynamicDirectBypass = true

	if err := setRoutingOptions(&options, hopt); err != nil {
		t.Fatal(err)
	}

	if options.Route == nil {
		t.Fatal("expected route options")
	}
	if options.Route.FindProcess != C.IsWindows {
		t.Fatalf("expected FindProcess=%v for dynamic direct bypass TUN, got %v", C.IsWindows, options.Route.FindProcess)
	}
}
