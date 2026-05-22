package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestSetRoutingOptionsAddsProcessDirectRuleWhenEnabled(t *testing.T) {
	options := option.Options{DNS: &option.DNSOptions{}}
	if err := setRoutingOptions(&options, &HiddifyOptions{
		RouteOptions: RouteOptions{
			EnableProcessDirectRules: true,
			ProcessDirectRuleNames:   []string{"WXWork.exe", "WeChat.exe"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	rule := findRouteRuleByProcessName(options.Route.Rules, "WXWork.exe")
	if rule == nil {
		t.Fatal("expected process direct route rule")
	}
	if rule.Action != C.RuleActionTypeRoute || rule.RouteOptions.Outbound != OutboundDirectTag {
		t.Fatalf("expected direct route action, got action=%q outbound=%q", rule.Action, rule.RouteOptions.Outbound)
	}
	if !containsString(rule.ProcessName, "WeChat.exe") {
		t.Fatalf("expected process names to include WeChat.exe, got %#v", rule.ProcessName)
	}
}

func TestSetRoutingOptionsSkipsProcessDirectRuleWhenDisabled(t *testing.T) {
	options := option.Options{DNS: &option.DNSOptions{}}
	if err := setRoutingOptions(&options, &HiddifyOptions{
		RouteOptions: RouteOptions{
			EnableProcessDirectRules: false,
			ProcessDirectRuleNames:   []string{"WXWork.exe"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	if rule := findRouteRuleByProcessName(options.Route.Rules, "WXWork.exe"); rule != nil {
		t.Fatalf("expected no process direct route rule, got %#v", rule)
	}
}

func TestSetRoutingOptionsKeepsCustomRuleBeforeProcessDirectRule(t *testing.T) {
	options := option.Options{DNS: &option.DNSOptions{}}
	if err := setRoutingOptions(&options, &HiddifyOptions{
		Rules: []Rule{
			{
				Enabled:      true,
				Name:         "Proxy WeChat",
				Outbound:     Outbound_proxy,
				ProcessNames: []string{"WeChat.exe"},
			},
		},
		RouteOptions: RouteOptions{
			EnableProcessDirectRules: true,
			ProcessDirectRuleNames:   []string{"WeChat.exe"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	first := findRouteRuleByProcessName(options.Route.Rules, "WeChat.exe")
	if first == nil {
		t.Fatal("expected process route rule")
	}
	if first.RouteOptions.Outbound != OutboundMainDetour {
		t.Fatalf("expected custom proxy rule to be matched first, got outbound=%q", first.RouteOptions.Outbound)
	}
}
