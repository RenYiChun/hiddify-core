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

func TestSetOutboundsAddsMicrosoftUpdateProxyGroupFilteringDownloadUnstableKeywords(t *testing.T) {
	var options option.Options
	staticIPs := map[string][]string{}
	input := &option.Options{
		Outbounds: []option.Outbound{
			{
				Type:    C.TypeVLESS,
				Tag:     "209.87.93.20 tls_h2 grpc direct vless § 443 1",
				Options: &option.VLESSOutboundOptions{},
			},
			{
				Type:    C.TypeVMess,
				Tag:     "209.87.93.20 tls xhttp direct vmess dl=h2 § 443 1",
				Options: &option.VMessOutboundOptions{},
			},
			{
				Type:    C.TypeVMess,
				Tag:     "209.87.93.20 http httpupgrade direct vmess § 80 1",
				Options: &option.VMessOutboundOptions{},
			},
			{
				Type:    C.TypeVLESS,
				Tag:     "209.87.93.20 h3_quic xhttp direct vless dl=h1 § 443 1",
				Options: &option.VLESSOutboundOptions{},
			},
			{
				Type:    C.TypeNaive,
				Tag:     "209.87.93.20 NaiveTLS § 443 1",
				Options: &option.NaiveOutboundOptions{},
			},
			{
				Type:    C.TypeTUIC,
				Tag:     "209.87.93.20 TUIC § 43553 1",
				Options: &option.TUICOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "209.87.93.20 SSH § 40991 1",
				Options: &option.DirectOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "209.87.93.20 Hysteria2 § 52726 1",
				Options: &option.DirectOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "209.87.93.20 MieruTCP § 0 1",
				Options: &option.DirectOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "209.87.93.20 WireGuard § 59772 1",
				Options: &option.DirectOutboundOptions{},
			},
		},
	}

	if err := setOutbounds(&options, input, &HiddifyOptions{}, &staticIPs); err != nil {
		t.Fatal(err)
	}

	outbound := findTestOutbound(options.Outbounds, OutboundMicrosoftUpdateProxyTag)
	if outbound == nil {
		t.Fatal("expected Microsoft update proxy outbound group")
	}
	urlTestOptions, ok := outbound.Options.(*option.URLTestOutboundOptions)
	if !ok {
		t.Fatalf("expected URL-test options for %q, got %T", outbound.Tag, outbound.Options)
	}
	expected := []string{
		"209.87.93.20 tls_h2 grpc direct vless § 443 1",
		"209.87.93.20 tls xhttp direct vmess dl=h2 § 443 1",
		"209.87.93.20 http httpupgrade direct vmess § 80 1",
	}
	if !stringSlicesEqual(urlTestOptions.Outbounds, expected) {
		t.Fatalf("expected Microsoft update proxy outbounds %#v, got %#v", expected, urlTestOptions.Outbounds)
	}
	expectedURL := "http://1d.tlu.dl.delivery.mp.microsoft.com/"
	if urlTestOptions.URL != expectedURL {
		t.Fatalf("expected Microsoft update proxy URL-test URL %q, got %q", expectedURL, urlTestOptions.URL)
	}
	if urlTestOptions.InterruptExistConnections {
		t.Fatalf("expected %q not to interrupt existing connections", outbound.Tag)
	}
}

func TestSetOutboundsAddsGooglePlayProxyGroupFilteringCdnUnstableKeywords(t *testing.T) {
	var options option.Options
	staticIPs := map[string][]string{}
	input := &option.Options{
		Outbounds: []option.Outbound{
			{
				Type:    C.TypeVLESS,
				Tag:     "209.87.93.20 tls_h2 grpc direct vless § 443 1",
				Options: &option.VLESSOutboundOptions{},
			},
			{
				Type:    C.TypeVMess,
				Tag:     "209.87.93.20 tls xhttp direct vmess dl=h2 § 443 1",
				Options: &option.VMessOutboundOptions{},
			},
			{
				Type:    C.TypeVMess,
				Tag:     "209.87.93.20 tls grpc direct vmess § 443 1",
				Options: &option.VMessOutboundOptions{},
			},
			{
				Type:    C.TypeVMess,
				Tag:     "209.87.93.20 http httpupgrade direct vmess § 80 1",
				Options: &option.VMessOutboundOptions{},
			},
			{
				Type:    C.TypeVMess,
				Tag:     "209.87.93.20 tls httpupgrade direct vmess § 443 1",
				Options: &option.VMessOutboundOptions{},
			},
			{
				Type:    C.TypeVLESS,
				Tag:     "209.87.93.20 h3_quic xhttp direct vless dl=h1 § 443 1",
				Options: &option.VLESSOutboundOptions{},
			},
			{
				Type:    C.TypeNaive,
				Tag:     "209.87.93.20 NaiveTLS § 443 1",
				Options: &option.NaiveOutboundOptions{},
			},
			{
				Type:    C.TypeTUIC,
				Tag:     "209.87.93.20 TUIC § 43553 1",
				Options: &option.TUICOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "209.87.93.20 SSH § 40991 1",
				Options: &option.DirectOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "209.87.93.20 Hysteria2 § 52726 1",
				Options: &option.DirectOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "209.87.93.20 MieruTCP § 0 1",
				Options: &option.DirectOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "209.87.93.20 WireGuard § 59772 1",
				Options: &option.DirectOutboundOptions{},
			},
		},
	}

	if err := setOutbounds(&options, input, &HiddifyOptions{}, &staticIPs); err != nil {
		t.Fatal(err)
	}

	outbound := findTestOutbound(options.Outbounds, OutboundGooglePlayProxyTag)
	if outbound == nil {
		t.Fatal("expected Google Play proxy outbound group")
	}
	urlTestOptions, ok := outbound.Options.(*option.URLTestOutboundOptions)
	if !ok {
		t.Fatalf("expected URL-test options for %q, got %T", outbound.Tag, outbound.Options)
	}
	expected := []string{
		"209.87.93.20 tls_h2 grpc direct vless § 443 1",
		"209.87.93.20 tls grpc direct vmess § 443 1",
	}
	if !stringSlicesEqual(urlTestOptions.Outbounds, expected) {
		t.Fatalf("expected Google Play proxy outbounds %#v, got %#v", expected, urlTestOptions.Outbounds)
	}
	expectedURL := "https://redirector.gvt1.com"
	if urlTestOptions.URL != expectedURL {
		t.Fatalf("expected Google Play proxy URL-test URL %q, got %q", expectedURL, urlTestOptions.URL)
	}
	if urlTestOptions.InterruptExistConnections {
		t.Fatalf("expected %q not to interrupt existing connections", outbound.Tag)
	}
}

func TestSetOutboundsAddsClaudeProxyGroupWithAnthropicHealthCheck(t *testing.T) {
	var options option.Options
	staticIPs := map[string][]string{}
	input := &option.Options{
		Outbounds: []option.Outbound{
			{
				Type:    C.TypeVLESS,
				Tag:     "209.87.93.20 tls_h2 grpc direct vless § 443 1",
				Options: &option.VLESSOutboundOptions{},
			},
			{
				Type:    C.TypeVMess,
				Tag:     "209.87.93.20 tls xhttp direct vmess dl=h2 § 443 1",
				Options: &option.VMessOutboundOptions{},
			},
			{
				Type:    C.TypeVMess,
				Tag:     "209.87.93.20 http httpupgrade direct vmess § 80 1",
				Options: &option.VMessOutboundOptions{},
			},
			{
				Type:    C.TypeVMess,
				Tag:     "209.87.93.20 tls httpupgrade direct vmess § 443 1",
				Options: &option.VMessOutboundOptions{},
			},
			{
				Type:    C.TypeVLESS,
				Tag:     "209.87.93.20 h3_quic xhttp direct vless dl=h1 § 443 1",
				Options: &option.VLESSOutboundOptions{},
			},
			{
				Type:    C.TypeNaive,
				Tag:     "209.87.93.20 NaiveTLS § 443 1",
				Options: &option.NaiveOutboundOptions{},
			},
			{
				Type:    C.TypeTUIC,
				Tag:     "209.87.93.20 TUIC § 43553 1",
				Options: &option.TUICOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "209.87.93.20 SSH § 40991 1",
				Options: &option.DirectOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "209.87.93.20 Hysteria2 § 52726 1",
				Options: &option.DirectOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "209.87.93.20 MieruTCP § 0 1",
				Options: &option.DirectOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "209.87.93.20 WireGuard § 59772 1",
				Options: &option.DirectOutboundOptions{},
			},
		},
	}

	if err := setOutbounds(&options, input, &HiddifyOptions{}, &staticIPs); err != nil {
		t.Fatal(err)
	}

	outbound := findTestOutbound(options.Outbounds, OutboundClaudeProxyTag)
	if outbound == nil {
		t.Fatal("expected Claude proxy outbound group")
	}
	urlTestOptions, ok := outbound.Options.(*option.URLTestOutboundOptions)
	if !ok {
		t.Fatalf("expected URL-test options for %q, got %T", outbound.Tag, outbound.Options)
	}
	expected := []string{
		"209.87.93.20 tls_h2 grpc direct vless § 443 1",
		"209.87.93.20 tls xhttp direct vmess dl=h2 § 443 1",
		"209.87.93.20 http httpupgrade direct vmess § 80 1",
		"209.87.93.20 tls httpupgrade direct vmess § 443 1",
	}
	if !stringSlicesEqual(urlTestOptions.Outbounds, expected) {
		t.Fatalf("expected Claude proxy outbounds %#v, got %#v", expected, urlTestOptions.Outbounds)
	}
	if urlTestOptions.URL != claudeProxyHealthCheckURL {
		t.Fatalf("expected Claude proxy URL-test URL %q, got %q", claudeProxyHealthCheckURL, urlTestOptions.URL)
	}
	if urlTestOptions.InterruptExistConnections {
		t.Fatalf("expected %q not to interrupt existing connections", outbound.Tag)
	}
}

func TestSetOutboundsFallsBackToAllProxyNodesWhenAllMatchExcludedKeywords(t *testing.T) {
	var options option.Options
	staticIPs := map[string][]string{}
	input := &option.Options{
		Outbounds: []option.Outbound{
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
		t.Fatalf("expected %q outbound to fall back to all proxy nodes", OutboundProcessStableProxyTag)
	}
	balancerOptions, ok := outbound.Options.(*option.BalancerOutboundOptions)
	if !ok {
		t.Fatalf("expected balancer options for %q, got %T", outbound.Tag, outbound.Options)
	}
	expected := []string{
		"209.87.93.20 NaiveTLS § 443 1",
		"209.87.93.20 h3_quic xhttp direct vless § 443 1",
		"209.87.93.20 TUIC § 43553 1",
	}
	if !stringSlicesEqual(balancerOptions.Outbounds, expected) {
		t.Fatalf("expected fallback outbounds %#v, got %#v", expected, balancerOptions.Outbounds)
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

func TestSetRoutingOptionsRoutesClaudeProcessesThroughDedicatedProxyWhenAvailable(t *testing.T) {
	options := option.Options{
		DNS: &option.DNSOptions{},
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

	if err := setRoutingOptions(&options, &HiddifyOptions{}); err != nil {
		t.Fatal(err)
	}

	rule := findRouteRuleByProcessName(options.Route.Rules, "claude.exe")
	if rule == nil {
		t.Fatal("expected Claude process proxy route rule")
	}
	if rule.Action != C.RuleActionTypeRoute || rule.RouteOptions.Outbound != OutboundClaudeProxyTag {
		t.Fatalf("expected Claude process proxy route action, got action=%q outbound=%q", rule.Action, rule.RouteOptions.Outbound)
	}
	if !containsString(rule.ProcessName, "Claude.exe") || !containsString(rule.ProcessName, "cowork-svc.exe") {
		t.Fatalf("expected Claude process names to include desktop and worker processes, got %#v", rule.ProcessName)
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
