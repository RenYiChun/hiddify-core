package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestSetOutboundsAddsProcessStableProxyGroupFilteringDefaultKeywords(t *testing.T) {
	var options option.Options
	staticIPs := map[string][]string{}
	input := &option.Options{
		Outbounds: []option.Outbound{
			{
				Type:    C.TypeDirect,
				Tag:     "209.87.93.20 tls httpupgrade direct vless § 443 1",
				Options: &option.DirectOutboundOptions{},
			},
			{
				Type:    C.TypeNaive,
				Tag:     "209.87.93.20 NaiveTLS § 443 1",
				Options: &option.NaiveOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "209.87.93.20 h3_quic xhttp direct vless § 443 1",
				Options: &option.DirectOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "209.87.93.20 TUIC § 43553 1",
				Options: &option.DirectOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "209.87.93.20 tls grpc direct vless § 443 1",
				Options: &option.DirectOutboundOptions{},
			},
		},
	}

	if err := setOutbounds(&options, input, &HiddifyOptions{
		RouteOptions: RouteOptions{
			EnableProcessStableProxyRules: true,
			ProcessStableProxyRuleNames:   []string{"codex.exe"},
		},
	}, &staticIPs); err != nil {
		t.Fatal(err)
	}

	outbound := findTestOutbound(options.Outbounds, OutboundProcessStableProxyTag)
	if outbound == nil {
		t.Fatalf("expected %q outbound to be generated", OutboundProcessStableProxyTag)
	}
	balancerOptions, ok := outbound.Options.(*option.BalancerOutboundOptions)
	if !ok {
		t.Fatalf("expected balancer options for %q, got %T", outbound.Tag, outbound.Options)
	}
	expected := []string{
		"209.87.93.20 tls httpupgrade direct vless § 443 1",
		"209.87.93.20 tls grpc direct vless § 443 1",
	}
	if !stringSlicesEqual(balancerOptions.Outbounds, expected) {
		t.Fatalf("expected filtered stable outbounds %#v, got %#v", expected, balancerOptions.Outbounds)
	}
	if balancerOptions.InterruptExistConnections {
		t.Fatalf("expected %q not to interrupt existing connections", OutboundProcessStableProxyTag)
	}
}

func TestSetRoutingOptionsAddsProcessStableProxyRuleWhenEnabled(t *testing.T) {
	options := option.Options{DNS: &option.DNSOptions{}}
	if err := setRoutingOptions(&options, &HiddifyOptions{
		RouteOptions: RouteOptions{
			EnableProcessStableProxyRules: true,
			ProcessStableProxyRuleNames:   []string{"codex.exe", "Codex.exe"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	rule := findRouteRuleByProcessName(options.Route.Rules, "codex.exe")
	if rule == nil {
		t.Fatal("expected process stable proxy route rule")
	}
	if rule.Action != C.RuleActionTypeRoute || rule.RouteOptions.Outbound != OutboundProcessStableProxyTag {
		t.Fatalf("expected stable proxy route action, got action=%q outbound=%q", rule.Action, rule.RouteOptions.Outbound)
	}
	if !containsString(rule.ProcessName, "Codex.exe") {
		t.Fatalf("expected process names to include Codex.exe, got %#v", rule.ProcessName)
	}
}

func TestSetRoutingOptionsKeepsProcessDirectBeforeProcessStableProxyRule(t *testing.T) {
	options := option.Options{DNS: &option.DNSOptions{}}
	if err := setRoutingOptions(&options, &HiddifyOptions{
		RouteOptions: RouteOptions{
			EnableProcessDirectRules:      true,
			ProcessDirectRuleNames:        []string{"codex.exe"},
			EnableProcessStableProxyRules: true,
			ProcessStableProxyRuleNames:   []string{"codex.exe"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	first := findRouteRuleByProcessName(options.Route.Rules, "codex.exe")
	if first == nil {
		t.Fatal("expected process route rule")
	}
	if first.RouteOptions.Outbound != OutboundDirectTag {
		t.Fatalf("expected direct process rule to be matched first, got outbound=%q", first.RouteOptions.Outbound)
	}
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
