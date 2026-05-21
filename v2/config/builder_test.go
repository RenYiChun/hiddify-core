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
			ProxyRouteConnectionLimit:  128,
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
	if !containsString(suffixes, "myqcloud.com") || !containsString(suffixes, "weixinbridge.com") {
		t.Fatalf("expected eager suffixes to include WeCom document domains, got %#v", suffixes)
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
