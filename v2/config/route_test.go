package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	dns "github.com/sagernet/sing-dns"
)

func TestSetRoutingOptionsUsesLocalBootstrapResolverForTun(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "other",
	}); err != nil {
		t.Fatal(err)
	}
	if options.Route == nil || options.Route.DefaultDomainResolver == nil {
		t.Fatal("expected route default domain resolver to be generated")
	}
	if options.Route.DefaultDomainResolver.Server != DNSLocalTag {
		t.Fatalf("expected TUN bootstrap resolver to use %q, got %q", DNSLocalTag, options.Route.DefaultDomainResolver.Server)
	}
}

func TestSetRoutingOptionsRoutesLoopbackReverseDNSToLocal(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "other",
	}); err != nil {
		t.Fatal(err)
	}

	localIndex := -1
	remoteIndex := -1
	for index, rule := range options.DNS.Rules {
		defaultRule := rule.DefaultOptions
		if containsString(defaultRule.Domain, "1.0.0.127.in-addr.arpa") {
			localIndex = index
			if defaultRule.RouteOptions.Server != DNSLocalTag {
				t.Fatalf("expected loopback reverse DNS to use %q, got %q", DNSLocalTag, defaultRule.RouteOptions.Server)
			}
			if defaultRule.RouteOptions.BypassIfFailed {
				t.Fatalf("expected loopback reverse DNS not to fall through: %+v", defaultRule)
			}
		}
		if defaultRule.RouteOptions.Server == DNSMultiRemoteTag {
			remoteIndex = index
		}
	}
	if localIndex == -1 {
		t.Fatal("expected loopback reverse DNS rule")
	}
	if remoteIndex == -1 {
		t.Fatal("expected final remote DNS rule")
	}
	if localIndex > remoteIndex {
		t.Fatalf("expected loopback reverse DNS before final remote DNS, got %d and %d", localIndex, remoteIndex)
	}
}

func TestSetRoutingOptionsResolvesClaudeLocalArtifactsInvalidLocally(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "other",
	}); err != nil {
		t.Fatal(err)
	}

	localIndex := -1
	remoteIndex := -1
	for index, rule := range options.DNS.Rules {
		defaultRule := rule.DefaultOptions
		if containsString(defaultRule.Domain, "local-artifacts.invalid") {
			localIndex = index
			if defaultRule.RouteOptions.Server != DNSLocalTag {
				t.Fatalf("expected local-artifacts.invalid to use %q, got %q", DNSLocalTag, defaultRule.RouteOptions.Server)
			}
			if defaultRule.RouteOptions.BypassIfFailed {
				t.Fatalf("expected local-artifacts.invalid DNS not to fall through: %+v", defaultRule)
			}
		}
		if defaultRule.RouteOptions.Server == DNSMultiRemoteTag {
			remoteIndex = index
		}
	}
	if localIndex == -1 {
		t.Fatal("expected local-artifacts.invalid DNS rule")
	}
	if remoteIndex == -1 {
		t.Fatal("expected final remote DNS rule")
	}
	if localIndex > remoteIndex {
		t.Fatalf("expected local-artifacts.invalid DNS before final remote DNS, got %d and %d", localIndex, remoteIndex)
	}
}

func TestSetRoutingOptionsRejectsIPv6DestinationsWhenIPv4Only(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			IPv6Mode:  option.DomainStrategy(dns.DomainStrategyUseIPv4),
			BypassLAN: true,
		},
		Region: "other",
	}); err != nil {
		t.Fatal(err)
	}

	hijackDNSIndex := -1
	ipv6RejectIndex := -1
	for index, rule := range options.Route.Rules {
		defaultRule := rule.DefaultOptions
		if defaultRule.Action == C.RuleActionTypeHijackDNS {
			hijackDNSIndex = index
		}
		if defaultRule.IPVersion == 6 && defaultRule.Action == C.RuleActionTypeReject {
			ipv6RejectIndex = index
			if defaultRule.RejectOptions.Method != C.RuleActionRejectMethodDefault {
				t.Fatalf("expected default reject method, got %q", defaultRule.RejectOptions.Method)
			}
		}
	}
	if hijackDNSIndex == -1 {
		t.Fatal("expected DNS hijack rule")
	}
	if ipv6RejectIndex == -1 {
		t.Fatal("expected IPv6 reject route rule")
	}
	if hijackDNSIndex > ipv6RejectIndex {
		t.Fatalf("expected DNS hijack before IPv6 reject, got %d and %d", hijackDNSIndex, ipv6RejectIndex)
	}
}

func TestSetRoutingOptionsUsesIPv4OnlyRemoteDNSWhenIPv6Disabled(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
			RemoteDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyAsIS),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			IPv6Mode:  option.DomainStrategy(dns.DomainStrategyUseIPv4),
			BypassLAN: true,
		},
		Region: "other",
	}); err != nil {
		t.Fatal(err)
	}

	for _, rule := range options.DNS.Rules {
		defaultRule := rule.DefaultOptions
		if defaultRule.RouteOptions.Server != DNSMultiRemoteTag {
			continue
		}
		if defaultRule.RouteOptions.Strategy != option.DomainStrategy(dns.DomainStrategyUseIPv4) {
			t.Fatalf("expected final remote DNS strategy to be IPv4-only, got %s", defaultRule.RouteOptions.Strategy)
		}
		return
	}
	t.Fatal("expected final remote DNS rule")
}

func TestSetRoutingOptionsKeepsIPv6DestinationsWhenIPv6ModeIsNotIPv4Only(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			IPv6Mode:  option.DomainStrategy(dns.DomainStrategyAsIS),
			BypassLAN: true,
		},
		Region: "other",
	}); err != nil {
		t.Fatal(err)
	}

	for _, rule := range options.Route.Rules {
		defaultRule := rule.DefaultOptions
		if defaultRule.IPVersion == 6 && defaultRule.Action == C.RuleActionTypeReject {
			t.Fatalf("expected no IPv6 reject rule outside IPv4-only mode, got %+v", defaultRule)
		}
	}
}

func TestSetRoutingOptionsAddsTunSniffOverrideAfterPrivateBypass(t *testing.T) {
	path := filepath.Join(t.TempDir(), "direct-domain-suffixes.txt")
	if err := os.WriteFile(path, []byte("custom.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	options := option.Options{
		DNS: &option.DNSOptions{},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN:                   true,
			DirectDomainSuffixRulesPath: path,
		},
		Region: "other",
	}); err != nil {
		t.Fatal(err)
	}

	privateBypassIndex := -1
	overrideIndex := -1
	domainDirectIndex := -1
	for index, rule := range options.Route.Rules {
		defaultRule := rule.DefaultOptions
		if defaultRule.IPIsPrivate && defaultRule.RouteOptions.Outbound == OutboundDirectTag {
			privateBypassIndex = index
		}
		if defaultRule.Action == C.RuleActionTypeSniff &&
			containsString(defaultRule.Inbound, InboundTUNTag) &&
			defaultRule.SniffOptions.OverrideDestination {
			overrideIndex = index
		}
		if containsString(defaultRule.DomainSuffix, "custom.example.com") &&
			defaultRule.RouteOptions.Outbound == OutboundDirectTag {
			domainDirectIndex = index
		}
	}
	if privateBypassIndex == -1 {
		t.Fatal("expected private bypass route rule")
	}
	if overrideIndex == -1 {
		t.Fatal("expected TUN sniff override route rule")
	}
	if domainDirectIndex == -1 {
		t.Fatal("expected domain direct route rule")
	}
	if !(privateBypassIndex < overrideIndex && overrideIndex < domainDirectIndex) {
		t.Fatalf("expected private bypass < TUN sniff override < domain direct, got %d, %d, %d", privateBypassIndex, overrideIndex, domainDirectIndex)
	}
}

func TestSetRoutingOptionsDoesNotAddTunSniffOverrideOutsideTun(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			SetSystemProxy: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "other",
	}); err != nil {
		t.Fatal(err)
	}

	for _, rule := range options.Route.Rules {
		defaultRule := rule.DefaultOptions
		if defaultRule.Action == C.RuleActionTypeSniff &&
			defaultRule.SniffOptions.OverrideDestination {
			t.Fatalf("expected no sniff override outside TUN, got %+v", defaultRule)
		}
	}
}

func TestSetRoutingOptionsAddsDynamicDirectBypassIPRules(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	future := time.Now().Add(time.Hour).Format(time.RFC3339Nano)
	past := time.Now().Add(-time.Hour).Format(time.RFC3339Nano)
	if err := os.WriteFile(cachePath, []byte(`[
		{"host":"smartservice.console.aliyun.com","ip":"47.89.238.193","expires_at":"`+future+`"},
		{"host":"smartservice.console.aliyun.com","ip":"47.88.73.20","expires_at":"`+future+`"},
		{"host":"chatgpt.com","ip":"172.64.155.209","expires_at":"`+future+`"},
		{"host":"cp.cloudflare.com","ip":"104.18.32.47","process_name":"HiddifyCustom.exe","process_path":"D:\\github.com\\hiddify-app\\build\\windows\\x64\\runner\\Debug\\HiddifyCustom.exe","expires_at":"`+future+`"},
		{"host":"expired.example.com","ip":"47.88.73.19","expires_at":"`+past+`"},
		{"host":"private.example.com","ip":"192.168.1.20","expires_at":"`+future+`"}
	]`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN:                        true,
			EnableDynamicDirectBypass:        true,
			DynamicDirectBypassRoutesPath:    cachePath,
			DynamicDirectBypassMaxRoutes:     128,
			DynamicDirectBypassMaxRoutesHost: 32,
		},
		Region: "other",
	}); err != nil {
		t.Fatal(err)
	}

	rule := findDynamicDirectBypassRule(options.Route.Rules)
	if rule == nil {
		t.Fatal("expected dynamic direct bypass route rule to be generated")
	}
	if rule.RouteOptions.Outbound != OutboundDirectTag {
		t.Fatalf("expected dynamic direct bypass rule to use %q, got %q", OutboundDirectTag, rule.RouteOptions.Outbound)
	}
	assertStringSet(t, rule.IPCIDR, []string{"47.89.238.193/32", "47.88.73.20/32"})
	domainRule := findDynamicDirectBypassDomainRule(options.Route.Rules)
	if domainRule == nil {
		t.Fatal("expected dynamic direct bypass domain route rule to be generated")
	}
	if domainRule.RouteOptions.Outbound != OutboundDirectTag {
		t.Fatalf("expected dynamic direct bypass domain rule to use %q, got %q", OutboundDirectTag, domainRule.RouteOptions.Outbound)
	}
	assertStringSet(t, domainRule.Domain, []string{"smartservice.console.aliyun.com"})
}

func TestSetRoutingOptionsAddsDynamicDirectBypassDomainRulesOutsideTun(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	future := time.Now().Add(time.Hour).Format(time.RFC3339Nano)
	if err := os.WriteFile(cachePath, []byte(`[
		{"host":"smartservice.console.aliyun.com","ip":"47.96.247.67","expires_at":"`+future+`"},
		{"host":"chatgpt.com","ip":"104.18.32.47","expires_at":"`+future+`"}
	]`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun:      false,
			SetSystemProxy: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN:                        true,
			EnableDynamicDirectBypass:        true,
			DynamicDirectBypassRoutesPath:    cachePath,
			DynamicDirectBypassMaxRoutes:     128,
			DynamicDirectBypassMaxRoutesHost: 32,
		},
		Region: "other",
	}); err != nil {
		t.Fatal(err)
	}

	domainRule := findDynamicDirectBypassDomainRule(options.Route.Rules)
	if domainRule == nil {
		t.Fatal("expected dynamic direct bypass domain route rule outside TUN")
	}
	if domainRule.RouteOptions.Outbound != OutboundDirectTag {
		t.Fatalf("expected dynamic direct bypass domain rule to use %q, got %q", OutboundDirectTag, domainRule.RouteOptions.Outbound)
	}
	assertStringSet(t, domainRule.Domain, []string{"smartservice.console.aliyun.com"})
}

func TestLoadDynamicDirectBypassRouteMatchersSkipsMicrosoftUpdateDeliveryEntries(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	future := time.Now().Add(time.Hour).Format(time.RFC3339Nano)
	if err := os.WriteFile(cachePath, []byte(`[
		{"host":"dl.delivery.mp.microsoft.com","ip":"14.29.45.71","reason":"direct","expires_at":"`+future+`"},
		{"host":"ctldl.windowsupdate.com","ip":"14.119.92.7","reason":"direct","expires_at":"`+future+`"},
		{"host":"dcat-b-tlu-net.trafficmanager.net","ip":"199.232.214.172","reason":"direct","expires_at":"`+future+`"},
		{"host":"bg.microsoft.map.fastly.net","ip":"199.232.210.172","reason":"direct","expires_at":"`+future+`"},
		{"host":"cdn.storeedgefd.dsx.mp.microsoft.com","ip":"23.43.187.13","reason":"direct","expires_at":"`+future+`"},
		{"host":"storeedge.microsoft.com","ip":"23.43.187.13","reason":"direct","expires_at":"`+future+`"},
		{"host":"storeedgefd.dsx.mp.microsoft.com","ip":"23.43.187.13","reason":"direct","expires_at":"`+future+`"},
		{"host":"array811.prod.do.dsp.mp.microsoft.com","ip":"13.107.246.74","reason":"direct","expires_at":"`+future+`"},
		{"host":"displaycatalog.mp.microsoft.com","ip":"150.171.109.149","reason":"direct","expires_at":"`+future+`"},
		{"host":"emdl.ws.microsoft.com","ip":"20.54.24.148","reason":"direct","expires_at":"`+future+`"},
		{"host":"smartservice.console.aliyun.com","ip":"47.89.238.193","reason":"direct","expires_at":"`+future+`"}
	]`), 0o644); err != nil {
		t.Fatal(err)
	}

	matchers := loadDynamicDirectBypassRouteMatchers(&HiddifyOptions{
		RouteOptions: RouteOptions{
			EnableDynamicDirectBypass:        true,
			DynamicDirectBypassRoutesPath:    cachePath,
			DynamicDirectBypassMaxRoutes:     128,
			DynamicDirectBypassMaxRoutesHost: 32,
		},
	}, time.Now())

	assertStringSet(t, matchers.domains, []string{"smartservice.console.aliyun.com"})
	assertStringSet(t, matchers.cidrs, []string{"47.89.238.193/32"})
}

func TestSetRoutingOptionsKeepsDirectBootstrapResolverOutsideTun(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "other",
	}); err != nil {
		t.Fatal(err)
	}
	if options.Route == nil || options.Route.DefaultDomainResolver == nil {
		t.Fatal("expected route default domain resolver to be generated")
	}
	if options.Route.DefaultDomainResolver.Server != DNSMultiDirectTag {
		t.Fatalf("expected non-TUN bootstrap resolver to use %q, got %q", DNSMultiDirectTag, options.Route.DefaultDomainResolver.Server)
	}
}

func TestSetRoutingOptionsUsesConfiguredDirectDnsRulesInTun(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		URLTestOptions: URLTestOptions{
			ConnectionTestUrls: []string{"http://captive.apple.com/hotspot-detect.html"},
		},
		Region: "cn",
	}); err != nil {
		t.Fatal(err)
	}

	regionServers := []string{}
	geoSiteServers := []string{}
	connectionTestServers := []string{}
	for _, rule := range options.DNS.Rules {
		if len(rule.DefaultOptions.DomainSuffix) > 0 && rule.DefaultOptions.DomainSuffix[0] == ".cn" {
			regionServers = append(regionServers, rule.DefaultOptions.RouteOptions.Server)
			if rule.DefaultOptions.RouteOptions.BypassIfFailed {
				t.Fatalf("expected TUN region direct DNS rule not to fall back to later DNS rules: %+v", rule.DefaultOptions)
			}
		}
		if containsString(rule.DefaultOptions.RuleSet, "geosite-cn") {
			geoSiteServers = append(geoSiteServers, rule.DefaultOptions.RouteOptions.Server)
			if rule.DefaultOptions.RouteOptions.BypassIfFailed {
				t.Fatalf("expected TUN geosite direct DNS rule not to fall back to later DNS rules: %+v", rule.DefaultOptions)
			}
		}
		for _, domain := range rule.DefaultOptions.Domain {
			if domain != "captive.apple.com" {
				continue
			}
			connectionTestServers = append(connectionTestServers, rule.DefaultOptions.RouteOptions.Server)
			if rule.DefaultOptions.RouteOptions.BypassIfFailed {
				t.Fatalf("expected TUN force-direct DNS rule not to fall back to later DNS rules: %+v", rule.DefaultOptions)
			}
		}
	}
	assertDNSRuleServers(t, regionServers, []string{DNSMultiDirectTag})
	assertDNSRuleServers(t, geoSiteServers, []string{DNSMultiDirectTag})
	assertDNSRuleServers(t, connectionTestServers, []string{DNSMultiDirectTag})
}

func TestSetRoutingOptionsKeepsConfiguredDirectDnsRulesOutsideTun(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "cn",
	}); err != nil {
		t.Fatal(err)
	}

	foundRegionRule := false
	for _, rule := range options.DNS.Rules {
		if len(rule.DefaultOptions.DomainSuffix) == 0 || rule.DefaultOptions.DomainSuffix[0] != ".cn" {
			continue
		}
		foundRegionRule = true
		if rule.DefaultOptions.RouteOptions.Server != DNSMultiDirectTag {
			t.Fatalf("expected non-TUN direct DNS rule to use %q, got %q", DNSMultiDirectTag, rule.DefaultOptions.RouteOptions.Server)
		}
		if rule.DefaultOptions.RouteOptions.BypassIfFailed {
			t.Fatalf("expected non-TUN direct DNS rule not to fall back to later DNS rules: %+v", rule.DefaultOptions)
		}
	}
	if !foundRegionRule {
		t.Fatal("expected region direct DNS rule")
	}
}

func TestSetRoutingOptionsAddsChinaWorkDirectRulesForTun(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "cn",
	}); err != nil {
		t.Fatal(err)
	}

	foundDNSRule := false
	foundDriveDNSRule := false
	foundCosDNSRule := false
	for _, rule := range options.DNS.Rules {
		hasWorkSuffix := containsString(rule.DefaultOptions.DomainSuffix, "work.weixin.qq.com")
		hasDriveSuffix := containsString(rule.DefaultOptions.DomainSuffix, "weixin.qq.com")
		hasCosSuffix := containsString(rule.DefaultOptions.DomainSuffix, "myqcloud.com")
		if !hasWorkSuffix && !hasDriveSuffix && !hasCosSuffix {
			continue
		}
		foundDNSRule = foundDNSRule || hasWorkSuffix
		foundDriveDNSRule = foundDriveDNSRule || hasDriveSuffix
		foundCosDNSRule = foundCosDNSRule || hasCosSuffix
		if rule.DefaultOptions.RouteOptions.Server != DNSMultiDirectTag {
			t.Fatalf("expected TUN work domain DNS rule to use configured direct DNS, got %q", rule.DefaultOptions.RouteOptions.Server)
		}
		if rule.DefaultOptions.RouteOptions.BypassIfFailed {
			t.Fatalf("expected explicit direct domain DNS rule not to fall back to later DNS rules: %+v", rule.DefaultOptions)
		}
	}
	if !foundDNSRule {
		t.Fatal("expected work domain direct DNS rule")
	}
	if !foundDriveDNSRule {
		t.Fatal("expected weixin.qq.com direct DNS rule for drive/doc.weixin.qq.com")
	}
	if !foundCosDNSRule {
		t.Fatal("expected myqcloud.com direct DNS rule for WeCom microdisk COS files")
	}
	for _, suffix := range []string{"servicewechat.com", "weapp.tencentcloudapi.com", "wxqcloud.qq.com.cn"} {
		found := false
		for _, rule := range options.DNS.Rules {
			if !containsString(rule.DefaultOptions.DomainSuffix, suffix) {
				continue
			}
			found = true
			if rule.DefaultOptions.RouteOptions.Server != DNSMultiDirectTag {
				t.Fatalf("expected %s direct DNS rule to use %q, got %q", suffix, DNSMultiDirectTag, rule.DefaultOptions.RouteOptions.Server)
			}
			if rule.DefaultOptions.RouteOptions.BypassIfFailed {
				t.Fatalf("expected %s direct DNS rule not to fall back to later DNS rules", suffix)
			}
		}
		if !found {
			t.Fatalf("expected %s direct DNS rule for WeChat DevTools preview", suffix)
		}
	}

	foundRouteRule := false
	foundDriveRouteRule := false
	foundCosRouteRule := false
	for _, rule := range options.Route.Rules {
		defaultRule := rule.DefaultOptions
		hasWorkSuffix := containsString(defaultRule.DomainSuffix, "work.weixin.qq.com")
		hasDriveSuffix := containsString(defaultRule.DomainSuffix, "weixin.qq.com")
		hasCosSuffix := containsString(defaultRule.DomainSuffix, "myqcloud.com")
		if !hasWorkSuffix && !hasDriveSuffix && !hasCosSuffix {
			continue
		}
		foundRouteRule = foundRouteRule || hasWorkSuffix
		foundDriveRouteRule = foundDriveRouteRule || hasDriveSuffix
		foundCosRouteRule = foundCosRouteRule || hasCosSuffix
		if defaultRule.RouteOptions.Outbound != OutboundDirectTag {
			t.Fatalf("expected work domain route rule to use %q, got %q", OutboundDirectTag, defaultRule.RouteOptions.Outbound)
		}
	}
	if !foundRouteRule {
		t.Fatal("expected work domain direct route rule")
	}
	if !foundDriveRouteRule {
		t.Fatal("expected weixin.qq.com direct route rule for drive/doc.weixin.qq.com")
	}
	if !foundCosRouteRule {
		t.Fatal("expected myqcloud.com direct route rule for WeCom microdisk COS files")
	}
	for _, suffix := range []string{"servicewechat.com", "weapp.tencentcloudapi.com", "wxqcloud.qq.com.cn"} {
		found := false
		for _, rule := range options.Route.Rules {
			if !containsString(rule.DefaultOptions.DomainSuffix, suffix) {
				continue
			}
			found = true
			if rule.DefaultOptions.RouteOptions.Outbound != OutboundDirectTag {
				t.Fatalf("expected %s route rule to use %q, got %q", suffix, OutboundDirectTag, rule.DefaultOptions.RouteOptions.Outbound)
			}
		}
		if !found {
			t.Fatalf("expected %s direct route rule for WeChat DevTools preview", suffix)
		}
	}
}

func TestSetRoutingOptionsAddsDefaultDirectRulesOutsideChina(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "other",
	}); err != nil {
		t.Fatal(err)
	}

	foundDNSRule := false
	for _, rule := range options.DNS.Rules {
		if containsString(rule.DefaultOptions.DomainSuffix, "work.weixin.qq.com") {
			foundDNSRule = true
			if rule.DefaultOptions.RouteOptions.Server != DNSMultiDirectTag {
				t.Fatalf("expected TUN default direct DNS rule to use configured direct DNS, got %q", rule.DefaultOptions.RouteOptions.Server)
			}
			if rule.DefaultOptions.RouteOptions.BypassIfFailed {
				t.Fatalf("expected TUN default direct DNS rule not to fall back to later DNS rules: %+v", rule.DefaultOptions)
			}
		}
	}
	if !foundDNSRule {
		t.Fatal("expected default direct DNS rule outside China region")
	}
}

func TestSetRoutingOptionsAvoidsGeoIPDirectRouteInTun(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "cn",
	}); err != nil {
		t.Fatal(err)
	}

	foundGeoSiteDirect := false
	for _, rule := range options.Route.Rules {
		if rule.DefaultOptions.RouteOptions.Outbound != OutboundDirectTag {
			continue
		}
		if containsString(rule.DefaultOptions.RuleSet, "geoip-cn") {
			t.Fatal("expected TUN route rules not to direct by geoip-cn; Google CN edge IPs must still use proxy unless matched by domain")
		}
		if containsString(rule.DefaultOptions.RuleSet, "geosite-cn") {
			foundGeoSiteDirect = true
		}
	}
	if !foundGeoSiteDirect {
		t.Fatal("expected TUN route rules to keep geosite-cn direct routing")
	}
}

func TestSetRoutingOptionsProxiesMicrosoftUpdateForEveryRegion(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		region    string
		enableTun bool
	}{
		{name: "cn-tun", region: "cn", enableTun: true},
		{name: "other-tun", region: "other", enableTun: true},
		{name: "us-tun", region: "us", enableTun: true},
		{name: "cn-system-proxy", region: "cn", enableTun: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			options := option.Options{
				DNS: &option.DNSOptions{},
			}

			if err := setRoutingOptions(&options, &HiddifyOptions{
				DNSOptions: DNSOptions{
					DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
				},
				InboundOptions: InboundOptions{
					EnableTun: testCase.enableTun,
				},
				RouteOptions: RouteOptions{
					BypassLAN: true,
				},
				Region: testCase.region,
			}); err != nil {
				t.Fatal(err)
			}

			assertMicrosoftUpdateProxyRules(t, options, OutboundMainDetour, DNSRemoteTag)
		})
	}
}

func TestMicrosoftUpdateProxyDomainSuffixesIncludeObservedStoreDownloadDependencies(t *testing.T) {
	suffixes := MicrosoftUpdateProxyDomainSuffixes()

	for _, expected := range []string{
		"t-ring.msedge.net",
		"t-ring-s2.msedge.net",
		"c2r.ts.cdn.office.net",
		"delivery.microsoft.com",
		"prod.do.dsp.mp.microsoft.com.edgekey.net",
		"d.akamaiedge.net",
		"dspw65.akamai.net",
		"fg.microsoft.map.fastly.net",
		"bg.microsoft.map.fastly.net",
		"wu-b-net.trafficmanager.net",
		"dcat-b-tlu-net.trafficmanager.net",
		"dcat-f-nlu-net.trafficmanager.net",
		"dcat-f-tlu-net.trafficmanager.net",
		"cdp-f-ssl-tlu-net.trafficmanager.net",
		"tlu.dl.delivery.mp.microsoft.com-c.edgesuite.net",
		"packageretrieval-gthdggdsd6g6bme6.westus2-01.azurewebsites.net",
	} {
		if !containsString(suffixes, expected) {
			t.Fatalf("expected Microsoft update proxy suffixes to include %q, got %#v", expected, suffixes)
		}
	}

	for _, controlDomain := range MicrosoftStoreControlDirectDomainSuffixes() {
		if containsString(suffixes, controlDomain) {
			t.Fatalf("expected Store control suffix %q not to be routed through Microsoft update file download proxy", controlDomain)
		}
	}
}

func TestMicrosoftStoreControlDomainsRouteThroughDirectFragment(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{
					{
						Type: C.DNSTypeHTTPS,
						Tag:  DNSMicrosoftUpdateRemoteTag,
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeURLTest,
				Tag:  OutboundMicrosoftUpdateProxyTag,
				Options: &option.URLTestOutboundOptions{
					Outbounds: []string{"209.87.93.20 tls_h2 grpc direct vless § 443 1"},
				},
			},
		},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "cn",
	}); err != nil {
		t.Fatal(err)
	}

	storeRouteIndex, _ := assertDirectFragmentDomainRules(t, options, "storeedgefd.dsx.mp.microsoft.com", DNSMultiDirectTag)
	microsoftRouteIndex, _ := assertMicrosoftUpdateProxyRules(t, options, OutboundMicrosoftUpdateProxyTag, DNSMicrosoftUpdateRemoteTag)
	if storeRouteIndex >= microsoftRouteIndex {
		t.Fatalf("expected Store control direct-fragment rule before Microsoft update file proxy rule, got store=%d microsoft=%d", storeRouteIndex, microsoftRouteIndex)
	}
	assertDirectFragmentDomainRules(t, options, "displaycatalog.mp.microsoft.com", DNSMultiDirectTag)
	assertDirectFragmentDomainRules(t, options, "dsp.mp.microsoft.com", DNSMultiDirectTag)
	assertDirectFragmentDomainRules(t, options, "storeedge.microsoft.com", DNSMultiDirectTag)
}

func TestMicrosoftStoreCdnRoutesThroughUpdateProxyBeforeStoreControlDirect(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{
					{
						Type: C.DNSTypeHTTPS,
						Tag:  DNSMicrosoftUpdateRemoteTag,
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeURLTest,
				Tag:  OutboundMicrosoftUpdateProxyTag,
				Options: &option.URLTestOutboundOptions{
					Outbounds: []string{"209.87.93.20 tls_h2 grpc direct vless § 443 1"},
				},
			},
		},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "cn",
	}); err != nil {
		t.Fatal(err)
	}

	cdnRouteIndex, cdnDNSIndex := assertForcedProxyDomainRules(t, options, "cdn.storeedgefd.dsx.mp.microsoft.com", OutboundMicrosoftUpdateProxyTag, DNSMicrosoftUpdateRemoteTag)
	storeRouteIndex, storeDNSIndex := assertDirectFragmentDomainRules(t, options, "storeedgefd.dsx.mp.microsoft.com", DNSMultiDirectTag)
	if cdnRouteIndex >= storeRouteIndex {
		t.Fatalf("expected Store CDN proxy route before generic Store direct route, got cdn=%d store=%d", cdnRouteIndex, storeRouteIndex)
	}
	if cdnDNSIndex >= storeDNSIndex {
		t.Fatalf("expected Store CDN proxy DNS before generic Store direct DNS, got cdn=%d store=%d", cdnDNSIndex, storeDNSIndex)
	}
}

func TestGooglePlayDomainsAreExcludedFromDynamicDirectBypass(t *testing.T) {
	for _, host := range []string{
		"rr3---sn-j5o76n7e.xn--ngstr-lra8j.com",
		"android.clients.google.com",
		"services.googleapis.cn",
		"play.googleapis.com",
	} {
		if !IsDynamicDirectBypassExcludedHost(host) {
			t.Fatalf("expected Google Play host %q to be excluded from dynamic direct bypass", host)
		}
	}
}

func TestAndroidConnectivityCheckCanUseDynamicDirectBypass(t *testing.T) {
	if IsDynamicDirectBypassExcludedHost("connectivitycheck.gstatic.com") {
		t.Fatal("expected Android connectivity check host to remain eligible for dynamic direct bypass")
	}
}

func TestCriticalGoogleInfrastructureIsExcludedFromDynamicDirectBypass(t *testing.T) {
	for _, host := range []string{
		"www.google.com",
		"about.google",
		"www.gstatic.com",
		"fonts.gstatic.com",
		"ssl.gstatic.com",
		"c.pki.goog",
	} {
		if !IsDynamicDirectBypassExcludedHost(host) {
			t.Fatalf("expected critical Google host %q to be excluded from dynamic direct bypass", host)
		}
	}
}

func TestClaudeDomainsAreExcludedFromDynamicDirectBypass(t *testing.T) {
	for _, host := range []string{
		"a-api.anthropic.com",
		"assets-proxy.anthropic.com",
		"s-cdn.anthropic.com",
		"downloads.claude.ai",
		"claude.ai",
		"www.claude.com",
		"files.claudemcpcontent.com",
	} {
		if !IsDynamicDirectBypassExcludedHost(host) {
			t.Fatalf("expected Claude host %q to be excluded from dynamic direct bypass", host)
		}
	}
}

func TestSetRoutingOptionsRoutesGooglePlayThroughForcedProxyRules(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "cn",
	}); err != nil {
		t.Fatal(err)
	}

	assertForcedProxyDomainRules(t, options, "xn--ngstr-lra8j.com", OutboundMainDetour, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "googleapis.cn", OutboundMainDetour, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "play.googleapis.com", OutboundMainDetour, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "www.gstatic.com", OutboundMainDetour, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "pki.goog", OutboundMainDetour, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "google", OutboundMainDetour, DNSRemoteTag)
}

func TestSetRoutingOptionsRoutesGooglePlayThroughMicrosoftUpdateProxyWithRemoteDNSWhenAvailable(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{
					{
						Type: C.DNSTypeHTTPS,
						Tag:  DNSMicrosoftUpdateRemoteTag,
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeURLTest,
				Tag:  OutboundMicrosoftUpdateProxyTag,
				Options: &option.URLTestOutboundOptions{
					Outbounds: []string{"209.87.93.20 tls_h2 grpc direct vless § 443 1"},
				},
			},
		},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "cn",
	}); err != nil {
		t.Fatal(err)
	}

	assertForcedProxyDomainRules(t, options, "xn--ngstr-lra8j.com", OutboundMicrosoftUpdateProxyTag, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "googleapis.cn", OutboundMicrosoftUpdateProxyTag, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "play.googleapis.com", OutboundMicrosoftUpdateProxyTag, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "www.gstatic.com", OutboundMainDetour, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "pki.goog", OutboundMainDetour, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "google", OutboundMainDetour, DNSRemoteTag)
}

func TestSetRoutingOptionsRoutesGooglePlayThroughDedicatedProxyWhenAvailable(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{
					{
						Type: C.DNSTypeHTTPS,
						Tag:  DNSMicrosoftUpdateRemoteTag,
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeURLTest,
				Tag:  OutboundMicrosoftUpdateProxyTag,
				Options: &option.URLTestOutboundOptions{
					Outbounds: []string{"209.87.93.20 tls_h2 grpc direct vless § 443 1"},
				},
			},
			{
				Type: C.TypeURLTest,
				Tag:  OutboundGooglePlayProxyTag,
				Options: &option.URLTestOutboundOptions{
					Outbounds: []string{"209.87.93.20 http httpupgrade direct vmess § 80 1"},
				},
			},
		},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "cn",
	}); err != nil {
		t.Fatal(err)
	}

	assertForcedProxyDomainRules(t, options, "xn--ngstr-lra8j.com", OutboundGooglePlayProxyTag, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "googleapis.cn", OutboundGooglePlayProxyTag, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "play.googleapis.com", OutboundGooglePlayProxyTag, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "www.gstatic.com", OutboundMainDetour, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "pki.goog", OutboundMainDetour, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "google", OutboundMainDetour, DNSRemoteTag)
}

func TestSetRoutingOptionsRoutesClaudeTrafficThroughDedicatedProxyButKeepsGenericRemoteDNS(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{
					{
						Type: C.DNSTypeHTTPS,
						Tag:  DNSClaudeRemoteTag,
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeURLTest,
				Tag:  OutboundClaudeProxyTag,
				Options: &option.URLTestOutboundOptions{
					Outbounds: []string{"209.87.93.20 tls_h2 grpc direct vless § 443 1"},
				},
			},
		},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "cn",
	}); err != nil {
		t.Fatal(err)
	}

	assertForcedProxyDomainRules(t, options, "anthropic.com", OutboundClaudeProxyTag, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "claude.ai", OutboundClaudeProxyTag, DNSRemoteTag)
	assertForcedProxyDomainRules(t, options, "claudemcpcontent.com", OutboundClaudeProxyTag, DNSRemoteTag)
}

func TestSetRoutingOptionsRoutesMicrosoftUpdateThroughDedicatedProxyWhenAvailable(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{
					{
						Type: C.DNSTypeHTTPS,
						Tag:  DNSMicrosoftUpdateRemoteTag,
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: C.TypeBalancer,
				Tag:  OutboundMicrosoftUpdateProxyTag,
				Options: &option.BalancerOutboundOptions{
					Outbounds: []string{"209.87.93.20 tls_h2 grpc direct vless § 443 1"},
				},
			},
		},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "cn",
	}); err != nil {
		t.Fatal(err)
	}

	routeIndex, dnsIndex := assertMicrosoftUpdateProxyRules(t, options, OutboundMicrosoftUpdateProxyTag, DNSMicrosoftUpdateRemoteTag)
	if routeIndex < 0 || dnsIndex < 0 {
		t.Fatalf("expected Microsoft update route and DNS rules, got route=%d dns=%d", routeIndex, dnsIndex)
	}
}

func TestSetRoutingOptionsOrdersMicrosoftUpdateBeforeChinaDirectRulesInTun(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN: true,
		},
		Region: "cn",
	}); err != nil {
		t.Fatal(err)
	}

	proxyRuleIndex, proxyDNSRuleIndex := assertMicrosoftUpdateProxyRules(t, options, OutboundMainDetour, DNSRemoteTag)

	cnDirectRuleIndex := -1
	geositeDirectRuleIndex := -1
	for i, rule := range options.Route.Rules {
		defaultRule := rule.DefaultOptions
		if defaultRule.RouteOptions.Outbound != OutboundDirectTag {
			continue
		}
		if containsString(defaultRule.DomainSuffix, ".cn") && cnDirectRuleIndex < 0 {
			cnDirectRuleIndex = i
		}
		if containsString(defaultRule.RuleSet, "geosite-cn") && geositeDirectRuleIndex < 0 {
			geositeDirectRuleIndex = i
		}
	}
	if proxyRuleIndex < 0 {
		t.Fatal("expected Microsoft update proxy route rule")
	}
	if cnDirectRuleIndex < 0 || geositeDirectRuleIndex < 0 {
		t.Fatal("expected region direct route rules")
	}
	if proxyRuleIndex > cnDirectRuleIndex || proxyRuleIndex > geositeDirectRuleIndex {
		t.Fatalf("expected Microsoft update proxy route before region direct rules, got proxy=%d cn=%d geosite=%d", proxyRuleIndex, cnDirectRuleIndex, geositeDirectRuleIndex)
	}

	cnDirectDNSRuleIndex := -1
	geositeDirectDNSRuleIndex := -1
	for i, rule := range options.DNS.Rules {
		defaultRule := rule.DefaultOptions
		if defaultRule.RouteOptions.Server != DNSMultiDirectTag {
			continue
		}
		if containsString(defaultRule.DomainSuffix, ".cn") && cnDirectDNSRuleIndex < 0 {
			cnDirectDNSRuleIndex = i
		}
		if containsString(defaultRule.RuleSet, "geosite-cn") && geositeDirectDNSRuleIndex < 0 {
			geositeDirectDNSRuleIndex = i
		}
	}
	if proxyDNSRuleIndex < 0 {
		t.Fatal("expected Microsoft update proxy DNS rule")
	}
	if cnDirectDNSRuleIndex < 0 || geositeDirectDNSRuleIndex < 0 {
		t.Fatal("expected region direct DNS rules")
	}
	if proxyDNSRuleIndex > cnDirectDNSRuleIndex || proxyDNSRuleIndex > geositeDirectDNSRuleIndex {
		t.Fatalf("expected Microsoft update proxy DNS before region direct DNS rules, got proxy=%d cn=%d geosite=%d", proxyDNSRuleIndex, cnDirectDNSRuleIndex, geositeDirectDNSRuleIndex)
	}
}

func TestSetRoutingOptionsOrdersMicrosoftUpdateBeforeDynamicDirectBypassInTun(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
	}
	cachePath := filepath.Join(t.TempDir(), "dynamic-direct-bypass-routes.json")
	future := time.Now().Add(time.Hour).Format(time.RFC3339Nano)
	if err := os.WriteFile(cachePath, []byte(`[
		{"host":"smartservice.console.aliyun.com","ip":"47.89.238.193","reason":"direct","expires_at":"`+future+`"}
	]`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN:                        true,
			EnableDynamicDirectBypass:        true,
			DynamicDirectBypassRoutesPath:    cachePath,
			DynamicDirectBypassMaxRoutes:     128,
			DynamicDirectBypassMaxRoutesHost: 32,
		},
		Region: "cn",
	}); err != nil {
		t.Fatal(err)
	}

	sniffIndex := -1
	dynamicCIDRIndex := -1
	dynamicDomainIndex := -1
	for i, rule := range options.Route.Rules {
		defaultRule := rule.DefaultOptions
		if defaultRule.Action == C.RuleActionTypeSniff &&
			containsString(defaultRule.Inbound, InboundTUNTag) &&
			defaultRule.SniffOptions.OverrideDestination {
			sniffIndex = i
		}
		if containsString(defaultRule.IPCIDR, "47.89.238.193/32") &&
			defaultRule.RouteOptions.Outbound == OutboundDirectTag {
			dynamicCIDRIndex = i
		}
		if containsString(defaultRule.Domain, "smartservice.console.aliyun.com") &&
			defaultRule.RouteOptions.Outbound == OutboundDirectTag {
			dynamicDomainIndex = i
		}
	}
	microsoftUpdateIndex, _ := assertMicrosoftUpdateProxyRules(t, options, OutboundMainDetour, DNSRemoteTag)

	if sniffIndex < 0 || dynamicCIDRIndex < 0 || dynamicDomainIndex < 0 || microsoftUpdateIndex < 0 {
		t.Fatalf("expected sniff, Microsoft update, and dynamic direct rules, got sniff=%d microsoft=%d cidr=%d domain=%d",
			sniffIndex, microsoftUpdateIndex, dynamicCIDRIndex, dynamicDomainIndex)
	}
	if !(sniffIndex < microsoftUpdateIndex &&
		microsoftUpdateIndex < dynamicCIDRIndex &&
		microsoftUpdateIndex < dynamicDomainIndex) {
		t.Fatalf("expected TUN sniff < Microsoft update proxy < dynamic direct rules, got sniff=%d microsoft=%d cidr=%d domain=%d",
			sniffIndex, microsoftUpdateIndex, dynamicCIDRIndex, dynamicDomainIndex)
	}
}

func TestSetRoutingOptionsUsesLocalCountryRuleSetWhenCached(t *testing.T) {
	basePath := t.TempDir()
	directRulesPath := DefaultDirectDomainSuffixRulesPath(basePath)
	localRuleSetPath := DefaultCountryRuleSetPath(basePath, "geosite-cn")
	if err := os.MkdirAll(filepath.Dir(localRuleSetPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localRuleSetPath, []byte{1, 2, 3}, 0o644); err != nil {
		t.Fatal(err)
	}

	options := option.Options{DNS: &option.DNSOptions{}}
	hopt := DefaultHiddifyOptions()
	hopt.Region = "cn"
	hopt.EnableTun = true
	hopt.DirectDomainSuffixRulesPath = directRulesPath

	if err := setRoutingOptions(&options, hopt); err != nil {
		t.Fatal(err)
	}

	ruleSet, ok := findRuleSet(options.Route.RuleSet, "geosite-cn")
	if !ok {
		t.Fatal("expected geosite-cn rule-set")
	}
	if ruleSet.Type != C.RuleSetTypeLocal {
		t.Fatalf("expected geosite-cn to use local rule-set, got %q", ruleSet.Type)
	}
	expectedConfigPath := filepath.ToSlash(filepath.Join(RulesRelativeDir, "geosite-cn.srs"))
	if ruleSet.LocalOptions.Path != expectedConfigPath {
		t.Fatalf("expected local geosite-cn path %q, got %q", expectedConfigPath, ruleSet.LocalOptions.Path)
	}
}

func TestSetRoutingOptionsKeepsRemoteCountryRuleSetWithoutLocalCache(t *testing.T) {
	basePath := t.TempDir()
	options := option.Options{DNS: &option.DNSOptions{}}
	hopt := DefaultHiddifyOptions()
	hopt.Region = "cn"
	hopt.EnableTun = true
	hopt.DirectDomainSuffixRulesPath = DefaultDirectDomainSuffixRulesPath(basePath)

	if err := setRoutingOptions(&options, hopt); err != nil {
		t.Fatal(err)
	}

	ruleSet, ok := findRuleSet(options.Route.RuleSet, "geosite-cn")
	if !ok {
		t.Fatal("expected geosite-cn rule-set")
	}
	if ruleSet.Type != C.RuleSetTypeRemote {
		t.Fatalf("expected geosite-cn to use remote rule-set without a local cache, got %q", ruleSet.Type)
	}
	if ruleSet.RemoteOptions.URL != "https://raw.githubusercontent.com/hiddify/hiddify-geo/rule-set/country/geosite-cn.srs" {
		t.Fatalf("unexpected remote geosite-cn URL: %q", ruleSet.RemoteOptions.URL)
	}
}

func TestLoadDirectDomainSuffixRulesFileCreatesEditableDefaultFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules", "direct-domain-suffixes.txt")

	suffixes, err := LoadDirectDomainSuffixRulesFile(path, []string{"work.weixin.qq.com", "weixin.qq.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(suffixes, "work.weixin.qq.com") || !containsString(suffixes, "weixin.qq.com") {
		t.Fatalf("expected defaults to be loaded from newly created file, got %#v", suffixes)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(ParseDirectDomainSuffixRules(string(content)), "work.weixin.qq.com") {
		t.Fatalf("expected created file to contain editable defaults, got:\n%s", string(content))
	}
}

func TestDefaultDirectDomainSuffixRulesIncludeCloudLoginDependencies(t *testing.T) {
	suffixes := DefaultDirectDomainSuffixRules()

	for _, expected := range []string{
		"aliyun.com",
		"aliyuncs.com",
		"alicdn.com",
		"huaweicloud.com",
		"myhuaweicloud.com",
		"huaweicloudapis.com",
		"huaweicloudwaf.com",
		"huawei.com",
		"hicloud.com",
		"vmall.com",
		"hc-cdn.com",
		"hc-cdn.cn",
		"cdnhwc1.com",
		"cdnhwc2.com",
		"globalsign.com",
	} {
		if !containsString(suffixes, expected) {
			t.Fatalf("expected default direct suffix rules to include %q, got %#v", expected, suffixes)
		}
	}
}

func TestLoadDirectDomainSuffixRulesFileMigratesGeneratedDefaultFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules", "direct-domain-suffixes.txt")
	oldGeneratedContent := `# Hiddify direct domain suffix rules
# One domain suffix per line. Blank lines and lines beginning with # are ignored.
# Matching domains use direct DNS and direct route when the generated config starts.

work.weixin.qq.com
weixin.qq.com
`
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(oldGeneratedContent), 0o644); err != nil {
		t.Fatal(err)
	}

	suffixes, err := LoadDirectDomainSuffixRulesFile(path, []string{
		"work.weixin.qq.com",
		"weixin.qq.com",
		"aliyun.com",
		"aliyuncs.com",
		"alicdn.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"aliyun.com", "aliyuncs.com", "alicdn.com"} {
		if !containsString(suffixes, expected) {
			t.Fatalf("expected migrated generated file to include %q, got %#v", expected, suffixes)
		}
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	parsed := ParseDirectDomainSuffixRules(string(content))
	if !containsString(parsed, "aliyun.com") {
		t.Fatalf("expected generated file to be updated with new defaults, got:\n%s", string(content))
	}
}

func TestLoadDirectDomainSuffixRulesFileParsesEditableText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "direct-domain-suffixes.txt")
	if err := os.WriteFile(path, []byte(`
# comments and blank lines are ignored
WORK.WEIXIN.QQ.COM
*.example.com # inline comment is ignored
https://invalid.example.com
bad/path
work.weixin.qq.com
.cn
`), 0o644); err != nil {
		t.Fatal(err)
	}

	suffixes, err := LoadDirectDomainSuffixRulesFile(path, []string{"fallback.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"work.weixin.qq.com", "example.com", ".cn"}
	if len(suffixes) != len(want) {
		t.Fatalf("expected %#v, got %#v", want, suffixes)
	}
	for i, expected := range want {
		if suffixes[i] != expected {
			t.Fatalf("expected suffix %d to be %q, got %q in %#v", i, expected, suffixes[i], suffixes)
		}
	}
}

func TestSetRoutingOptionsLoadsEditableDirectRulesForEveryRegion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "direct-domain-suffixes.txt")
	if err := os.WriteFile(path, []byte("custom.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, region := range []string{"cn", "other", "us"} {
		t.Run(region, func(t *testing.T) {
			options := option.Options{
				DNS: &option.DNSOptions{},
			}

			if err := setRoutingOptions(&options, &HiddifyOptions{
				DNSOptions: DNSOptions{
					DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
				},
				InboundOptions: InboundOptions{
					EnableTun: true,
				},
				RouteOptions: RouteOptions{
					BypassLAN:                   true,
					DirectDomainSuffixRulesPath: path,
				},
				Region: region,
			}); err != nil {
				t.Fatal(err)
			}

			foundDNSRule := false
			for _, rule := range options.DNS.Rules {
				if !containsString(rule.DefaultOptions.DomainSuffix, "custom.example.com") {
					continue
				}
				foundDNSRule = true
				if rule.DefaultOptions.RouteOptions.Server != DNSMultiDirectTag {
					t.Fatalf("expected editable direct DNS rule to use configured direct DNS, got %q", rule.DefaultOptions.RouteOptions.Server)
				}
				if rule.DefaultOptions.RouteOptions.BypassIfFailed {
					t.Fatalf("expected editable direct DNS rule not to fall back to later DNS rules: %+v", rule.DefaultOptions)
				}
			}
			if !foundDNSRule {
				t.Fatal("expected editable suffix to be injected into DNS rules")
			}

			foundRouteRule := false
			for _, rule := range options.Route.Rules {
				if !containsString(rule.DefaultOptions.DomainSuffix, "custom.example.com") {
					continue
				}
				foundRouteRule = true
				if rule.DefaultOptions.RouteOptions.Outbound != OutboundDirectTag {
					t.Fatalf("expected editable route rule to use %q, got %q", OutboundDirectTag, rule.DefaultOptions.RouteOptions.Outbound)
				}
			}
			if !foundRouteRule {
				t.Fatal("expected editable suffix to be injected into route rules")
			}
		})
	}
}

func TestSetRoutingOptionsEditableDirectRulesDoNotFallbackToRemoteDNS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "direct-domain-suffixes.txt")
	if err := os.WriteFile(path, []byte("custom.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	options := option.Options{DNS: &option.DNSOptions{}}
	if err := setRoutingOptions(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN:                   true,
			DirectDomainSuffixRulesPath: path,
		},
		Region: "other",
	}); err != nil {
		t.Fatal(err)
	}

	found := false
	for _, rule := range options.DNS.Rules {
		if !containsString(rule.DefaultOptions.DomainSuffix, "custom.example.com") {
			continue
		}
		found = true
		if rule.DefaultOptions.RouteOptions.BypassIfFailed {
			t.Fatalf("expected editable direct domain DNS rule not to fall back to later DNS rules: %+v", rule.DefaultOptions)
		}
	}
	if !found {
		t.Fatal("expected editable direct domain DNS rule")
	}
}

func TestSetRoutingOptionsReloadsEditableDirectRulesOnEachBuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "direct-domain-suffixes.txt")
	if err := os.WriteFile(path, []byte("first.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hopts := &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsDomainStrategy: option.DomainStrategy(dns.DomainStrategyUseIPv4),
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
		RouteOptions: RouteOptions{
			BypassLAN:                   true,
			DirectDomainSuffixRulesPath: path,
		},
		Region: "other",
	}

	firstOptions := option.Options{DNS: &option.DNSOptions{}}
	if err := setRoutingOptions(&firstOptions, hopts); err != nil {
		t.Fatal(err)
	}
	if !dnsRulesContainSuffix(firstOptions.DNS.Rules, "first.example.com") {
		t.Fatal("expected first build to load first.example.com")
	}

	if err := os.WriteFile(path, []byte("second.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	secondOptions := option.Options{DNS: &option.DNSOptions{}}
	if err := setRoutingOptions(&secondOptions, hopts); err != nil {
		t.Fatal(err)
	}
	if !dnsRulesContainSuffix(secondOptions.DNS.Rules, "second.example.com") {
		t.Fatal("expected second build to reload second.example.com")
	}
	if dnsRulesContainSuffix(secondOptions.DNS.Rules, "first.example.com") {
		t.Fatal("expected second build not to reuse stale first.example.com")
	}
}

func dnsRulesContainSuffix(rules []option.DNSRule, suffix string) bool {
	for _, rule := range rules {
		if containsString(rule.DefaultOptions.DomainSuffix, suffix) {
			return true
		}
	}
	return false
}

func assertDNSRuleServers(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("expected DNS rule servers %#v, got %#v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected DNS rule servers %#v, got %#v", want, got)
		}
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func assertMicrosoftUpdateProxyRules(t *testing.T, options option.Options, expectedOutbound string, expectedDNSServer string) (routeIndex int, dnsIndex int) {
	t.Helper()
	routeIndex, dnsIndex = assertForcedProxyDomainRules(t, options, "delivery.mp.microsoft.com", expectedOutbound, expectedDNSServer)

	for _, rule := range options.Route.Rules {
		defaultRule := rule.DefaultOptions
		if containsString(defaultRule.DomainSuffix, "delivery.mp.microsoft.com") &&
			!containsString(defaultRule.DomainSuffix, "tlu.dl.delivery.mp.microsoft.com-c.edgesuite.net") {
			t.Fatal("expected Microsoft update route to include observed TLU download CDN suffix")
		}
	}
	return routeIndex, dnsIndex
}

func assertDirectFragmentDomainRules(t *testing.T, options option.Options, domainSuffix string, expectedDNSServer string) (routeIndex int, dnsIndex int) {
	t.Helper()
	routeIndex = -1
	for i, rule := range options.Route.Rules {
		defaultRule := rule.DefaultOptions
		if !containsString(defaultRule.DomainSuffix, domainSuffix) {
			continue
		}
		routeIndex = i
		if defaultRule.RouteOptions.Outbound != OutboundDirectFragmentTag {
			t.Fatalf("expected %s route to use %q, got %q", domainSuffix, OutboundDirectFragmentTag, defaultRule.RouteOptions.Outbound)
		}
	}
	if routeIndex < 0 {
		t.Fatalf("expected direct-fragment route rule for %s", domainSuffix)
	}

	dnsIndex = -1
	for i, rule := range options.DNS.Rules {
		defaultRule := rule.DefaultOptions
		if !containsString(defaultRule.DomainSuffix, domainSuffix) {
			continue
		}
		dnsIndex = i
		if defaultRule.RouteOptions.Server != expectedDNSServer {
			t.Fatalf("expected %s DNS to use %q, got %q", domainSuffix, expectedDNSServer, defaultRule.RouteOptions.Server)
		}
	}
	if dnsIndex < 0 {
		t.Fatalf("expected direct DNS rule for %s", domainSuffix)
	}

	return routeIndex, dnsIndex
}

func assertForcedProxyDomainRules(t *testing.T, options option.Options, domainSuffix string, expectedOutbound string, expectedDNSServer string) (routeIndex int, dnsIndex int) {
	t.Helper()
	routeIndex = -1
	for i, rule := range options.Route.Rules {
		defaultRule := rule.DefaultOptions
		if !containsString(defaultRule.DomainSuffix, domainSuffix) {
			continue
		}
		routeIndex = i
		if defaultRule.RouteOptions.Outbound != expectedOutbound {
			t.Fatalf("expected %s route to use %q, got %q", domainSuffix, expectedOutbound, defaultRule.RouteOptions.Outbound)
		}
	}
	if routeIndex < 0 {
		t.Fatalf("expected forced proxy route rule for %s", domainSuffix)
	}

	dnsIndex = -1
	for i, rule := range options.DNS.Rules {
		defaultRule := rule.DefaultOptions
		if !containsString(defaultRule.DomainSuffix, domainSuffix) {
			continue
		}
		dnsIndex = i
		if defaultRule.RouteOptions.Server != expectedDNSServer {
			t.Fatalf("expected %s DNS to use %q, got %q", domainSuffix, expectedDNSServer, defaultRule.RouteOptions.Server)
		}
		if defaultRule.RouteOptions.BypassIfFailed {
			t.Fatalf("expected %s DNS not to fall back to direct DNS", domainSuffix)
		}
	}
	if dnsIndex < 0 {
		t.Fatalf("expected forced proxy DNS rule for %s", domainSuffix)
	}

	return routeIndex, dnsIndex
}

func findDynamicDirectBypassRule(rules []option.Rule) *option.DefaultRule {
	for _, rule := range rules {
		defaultRule := rule.DefaultOptions
		if defaultRule.RouteOptions.Outbound != OutboundDirectTag {
			continue
		}
		if containsString(defaultRule.IPCIDR, "47.89.238.193/32") {
			return &defaultRule
		}
	}
	return nil
}

func findDynamicDirectBypassDomainRule(rules []option.Rule) *option.DefaultRule {
	for _, rule := range rules {
		defaultRule := rule.DefaultOptions
		if defaultRule.RouteOptions.Outbound != OutboundDirectTag {
			continue
		}
		if containsString(defaultRule.Domain, "smartservice.console.aliyun.com") {
			return &defaultRule
		}
	}
	return nil
}

func assertStringSet(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("expected values %#v, got %#v", want, got)
	}
	for _, item := range want {
		if !containsString(got, item) {
			t.Fatalf("expected values %#v, got %#v", want, got)
		}
	}
}

func findRuleSet(ruleSets []option.RuleSet, tag string) (option.RuleSet, bool) {
	for _, ruleSet := range ruleSets {
		if ruleSet.Tag == tag {
			return ruleSet, true
		}
	}
	return option.RuleSet{}, false
}
