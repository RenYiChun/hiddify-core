package config

import (
	"os"
	"path/filepath"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"google.golang.org/protobuf/proto"
)

func TestSetRoutingOptionsAddsCustomProcessDirectRule(t *testing.T) {
	options := option.Options{DNS: &option.DNSOptions{}}
	if err := setRoutingOptions(&options, &HiddifyOptions{
		Rules: []Rule{
			{
				Enabled:      true,
				Name:         "WeCom voice direct",
				Outbound:     Outbound_direct,
				ProcessNames: []string{"WXWorkXNet.exe"},
				Network:      Network_udp,
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	rule := findRouteRuleByProcessName(options.Route.Rules, "WXWorkXNet.exe")
	if rule == nil {
		t.Fatal("expected process_name route rule")
	}
	if rule.Action != C.RuleActionTypeRoute || rule.RouteOptions.Outbound != OutboundDirectTag {
		t.Fatalf("expected direct route action, got action=%q outbound=%q", rule.Action, rule.RouteOptions.Outbound)
	}
	if !containsString(rule.Network, "udp") {
		t.Fatalf("expected udp network matcher, got %#v", rule.Network)
	}
	if dnsRulesContainProcessName(options.DNS.Rules, "WXWorkXNet.exe") {
		t.Fatal("process-only rules must not generate DNS rules")
	}
}

func TestSetRoutingOptionsAddsCustomDomainProxyRouteAndDNSRule(t *testing.T) {
	options := option.Options{DNS: &option.DNSOptions{}}
	if err := setRoutingOptions(&options, &HiddifyOptions{
		Rules: []Rule{
			{
				Enabled:        true,
				Name:           "Proxy example",
				Outbound:       Outbound_proxy,
				DomainSuffixes: []string{"example.com"},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	routeRule := findRouteRuleByDomainSuffix(options.Route.Rules, "example.com")
	if routeRule == nil {
		t.Fatal("expected domain_suffix route rule")
	}
	if routeRule.Action != C.RuleActionTypeRoute || routeRule.RouteOptions.Outbound != OutboundMainDetour {
		t.Fatalf("expected proxy route action, got action=%q outbound=%q", routeRule.Action, routeRule.RouteOptions.Outbound)
	}

	dnsRule := findDNSRuleByDomainSuffix(options.DNS.Rules, "example.com")
	if dnsRule == nil {
		t.Fatal("expected domain_suffix DNS rule")
	}
	if dnsRule.Action != C.RuleActionTypeRoute || dnsRule.RouteOptions.Server != DNSRemoteTag {
		t.Fatalf("expected remote DNS route action, got action=%q server=%q", dnsRule.Action, dnsRule.RouteOptions.Server)
	}
}

func TestSetRoutingOptionsPreservesProcessMatcherOnCustomDNSRule(t *testing.T) {
	options := option.Options{DNS: &option.DNSOptions{}}
	if err := setRoutingOptions(&options, &HiddifyOptions{
		Rules: []Rule{
			{
				Enabled:        true,
				Name:           "WeCom domain direct",
				Outbound:       Outbound_direct,
				ProcessNames:   []string{"WXWork.exe"},
				DomainSuffixes: []string{"weixin.qq.com"},
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	dnsRule := findDNSRuleByDomainSuffix(options.DNS.Rules, "weixin.qq.com")
	if dnsRule == nil {
		t.Fatal("expected domain_suffix DNS rule")
	}
	if !containsString(dnsRule.ProcessName, "WXWork.exe") {
		t.Fatalf("expected DNS rule to preserve process_name matcher, got %#v", dnsRule.ProcessName)
	}
}

func TestSetRoutingOptionsLoadsCustomRouteRulesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route_rule.proto")
	data, err := proto.Marshal(&RouteRule{
		Rules: []*Rule{
			{
				Enabled:      true,
				Name:         "WeCom direct from file",
				Outbound:     Outbound_direct,
				ProcessNames: []string{"WXWork.exe"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	options := option.Options{DNS: &option.DNSOptions{}}
	if err := setRoutingOptions(&options, &HiddifyOptions{
		RouteOptions: RouteOptions{
			RouteRulesPath: path,
		},
	}); err != nil {
		t.Fatal(err)
	}

	rule := findRouteRuleByProcessName(options.Route.Rules, "WXWork.exe")
	if rule == nil {
		t.Fatal("expected process_name route rule loaded from route_rule.proto")
	}
	if rule.RouteOptions.Outbound != OutboundDirectTag {
		t.Fatalf("expected direct route action, got outbound=%q", rule.RouteOptions.Outbound)
	}
}

func TestSetRoutingOptionsIgnoresMissingCustomRouteRulesFile(t *testing.T) {
	options := option.Options{DNS: &option.DNSOptions{}}
	if err := setRoutingOptions(&options, &HiddifyOptions{
		RouteOptions: RouteOptions{
			RouteRulesPath: filepath.Join(t.TempDir(), "missing.proto"),
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSetRoutingOptionsIgnoresInvalidCustomRouteRulesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "route_rule.proto")
	if err := os.WriteFile(path, []byte("not a route rule protobuf"), 0o644); err != nil {
		t.Fatal(err)
	}

	options := option.Options{DNS: &option.DNSOptions{}}
	if err := setRoutingOptions(&options, &HiddifyOptions{
		RouteOptions: RouteOptions{
			RouteRulesPath: path,
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func findRouteRuleByProcessName(rules []option.Rule, processName string) *option.DefaultRule {
	for _, rule := range rules {
		defaultRule := rule.DefaultOptions
		if containsString(defaultRule.ProcessName, processName) {
			return &defaultRule
		}
	}
	return nil
}

func findRouteRuleByDomainSuffix(rules []option.Rule, suffix string) *option.DefaultRule {
	for _, rule := range rules {
		defaultRule := rule.DefaultOptions
		if containsString(defaultRule.DomainSuffix, suffix) {
			return &defaultRule
		}
	}
	return nil
}

func findDNSRuleByDomainSuffix(rules []option.DNSRule, suffix string) *option.DefaultDNSRule {
	for _, rule := range rules {
		defaultRule := rule.DefaultOptions
		if containsString(defaultRule.DomainSuffix, suffix) {
			return &defaultRule
		}
	}
	return nil
}

func dnsRulesContainProcessName(rules []option.DNSRule, processName string) bool {
	for _, rule := range rules {
		if containsString(rule.DefaultOptions.ProcessName, processName) {
			return true
		}
	}
	return false
}
