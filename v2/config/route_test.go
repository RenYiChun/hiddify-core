package config

import (
	"os"
	"path/filepath"
	"testing"

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

func TestSetRoutingOptionsUsesLocalDirectDnsRulesInTun(t *testing.T) {
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

	foundRegionRule := false
	foundConnectionTestRule := false
	for _, rule := range options.DNS.Rules {
		if len(rule.DefaultOptions.DomainSuffix) > 0 && rule.DefaultOptions.DomainSuffix[0] == ".cn" {
			foundRegionRule = true
			if rule.DefaultOptions.RouteOptions.Server != DNSLocalTag {
				t.Fatalf("expected TUN region DNS rule to use %q, got %q", DNSLocalTag, rule.DefaultOptions.RouteOptions.Server)
			}
			if !rule.DefaultOptions.RouteOptions.BypassIfFailed {
				t.Fatalf("expected TUN region DNS rule to bypass on failure: %+v", rule.DefaultOptions)
			}
		}
		for _, domain := range rule.DefaultOptions.Domain {
			if domain != "captive.apple.com" {
				continue
			}
			foundConnectionTestRule = true
			if rule.DefaultOptions.RouteOptions.Server != DNSLocalTag {
				t.Fatalf("expected TUN force-direct DNS rule to use %q, got %q", DNSLocalTag, rule.DefaultOptions.RouteOptions.Server)
			}
			if !rule.DefaultOptions.RouteOptions.BypassIfFailed {
				t.Fatalf("expected TUN force-direct DNS rule to bypass on failure: %+v", rule.DefaultOptions)
			}
		}
	}
	if !foundRegionRule {
		t.Fatal("expected region direct DNS rule")
	}
	if !foundConnectionTestRule {
		t.Fatal("expected connection test direct DNS rule")
	}
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
		if !rule.DefaultOptions.RouteOptions.BypassIfFailed {
			t.Fatalf("expected non-TUN direct DNS rule to bypass on failure: %+v", rule.DefaultOptions)
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
	for _, rule := range options.DNS.Rules {
		hasWorkSuffix := containsString(rule.DefaultOptions.DomainSuffix, "work.weixin.qq.com")
		hasDriveSuffix := containsString(rule.DefaultOptions.DomainSuffix, "weixin.qq.com")
		if !hasWorkSuffix && !hasDriveSuffix {
			continue
		}
		foundDNSRule = foundDNSRule || hasWorkSuffix
		foundDriveDNSRule = foundDriveDNSRule || hasDriveSuffix
		if rule.DefaultOptions.RouteOptions.Server != DNSLocalTag {
			t.Fatalf("expected TUN work domain DNS rule to use %q, got %q", DNSLocalTag, rule.DefaultOptions.RouteOptions.Server)
		}
		if !rule.DefaultOptions.RouteOptions.BypassIfFailed {
			t.Fatalf("expected TUN work domain DNS rule to bypass on failure: %+v", rule.DefaultOptions)
		}
	}
	if !foundDNSRule {
		t.Fatal("expected work domain direct DNS rule")
	}
	if !foundDriveDNSRule {
		t.Fatal("expected weixin.qq.com direct DNS rule for drive/doc.weixin.qq.com")
	}

	foundRouteRule := false
	foundDriveRouteRule := false
	for _, rule := range options.Route.Rules {
		defaultRule := rule.DefaultOptions
		hasWorkSuffix := containsString(defaultRule.DomainSuffix, "work.weixin.qq.com")
		hasDriveSuffix := containsString(defaultRule.DomainSuffix, "weixin.qq.com")
		if !hasWorkSuffix && !hasDriveSuffix {
			continue
		}
		foundRouteRule = foundRouteRule || hasWorkSuffix
		foundDriveRouteRule = foundDriveRouteRule || hasDriveSuffix
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
			if rule.DefaultOptions.RouteOptions.Server != DNSLocalTag {
				t.Fatalf("expected TUN default direct DNS rule to use %q, got %q", DNSLocalTag, rule.DefaultOptions.RouteOptions.Server)
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
				if rule.DefaultOptions.RouteOptions.Server != DNSLocalTag {
					t.Fatalf("expected editable direct DNS rule to use %q, got %q", DNSLocalTag, rule.DefaultOptions.RouteOptions.Server)
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

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
