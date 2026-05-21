package config

import (
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	dns "github.com/sagernet/sing-dns"
)

func TestSetDnsLeavesDirectIPDoHOnDefaultDirectDialer(t *testing.T) {
	directDNS := buildDirectDNSServer(t, "https://223.5.5.5/dns-query")

	dnsOptions, ok := directDNS.Options.(*option.RemoteHTTPSDNSServerOptions)
	if !ok {
		t.Fatalf("expected direct DNS to use HTTPS options, got %T", directDNS.Options)
	}
	if dnsOptions.Detour != "" {
		t.Fatalf("expected IP DoH direct DNS to use the default direct dialer, got detour %q", dnsOptions.Detour)
	}
}

func TestSetDnsLeavesPlainDirectIPOnDefaultDirectDialer(t *testing.T) {
	directDNS := buildDirectDNSServer(t, "223.5.5.5")

	dnsOptions, ok := directDNS.Options.(*option.RemoteDNSServerOptions)
	if !ok {
		t.Fatalf("expected direct DNS to use UDP options, got %T", directDNS.Options)
	}
	if dnsOptions.Detour != "" {
		t.Fatalf("expected plain IP direct DNS to use the default direct dialer, got detour %q", dnsOptions.Detour)
	}
}

func TestSetDnsKeepsFragmentForDirectDomainDoH(t *testing.T) {
	directDNS := buildDirectDNSServer(t, "https://dns.alidns.com/dns-query")

	dnsOptions, ok := directDNS.Options.(*option.RemoteHTTPSDNSServerOptions)
	if !ok {
		t.Fatalf("expected direct DNS to use HTTPS options, got %T", directDNS.Options)
	}
	if dnsOptions.Detour != OutboundDirectFragmentTag {
		t.Fatalf("expected domain DoH direct DNS detour to be %q, got %q", OutboundDirectFragmentTag, dnsOptions.Detour)
	}
}

func TestSetDnsKeepsConfiguredPlainTcpIPDirectDNSInTunMode(t *testing.T) {
	directDNS := buildTunDNSServer(t, DNSDirectTag, "tcp://8.8.8.8", "tcp://223.5.5.5")

	dnsOptions, ok := directDNS.Options.(*option.RemoteDNSServerOptions)
	if !ok {
		t.Fatalf("expected direct DNS to keep TCP options in TUN mode, got %T", directDNS.Options)
	}
	if directDNS.Type != C.DNSTypeTCP {
		t.Fatalf("expected direct DNS type to be %q in TUN mode, got %q", C.DNSTypeTCP, directDNS.Type)
	}
	if dnsOptions.Server != "223.5.5.5" {
		t.Fatalf("expected direct DNS server to remain 223.5.5.5, got %q", dnsOptions.Server)
	}
}

func TestSetDnsUsesDoHFallbackForRemoteNoWarpWhenTunRemoteDNSIsPlainTcpIP(t *testing.T) {
	remoteNoWarpDNS := buildTunDNSServer(t, DNSRemoteNoWarpTag, "tcp://8.8.8.8", "tcp://223.5.5.5")

	dnsOptions, ok := remoteNoWarpDNS.Options.(*option.RemoteHTTPSDNSServerOptions)
	if !ok {
		t.Fatalf("expected remote no-warp DNS to use HTTPS fallback in TUN mode, got %T", remoteNoWarpDNS.Options)
	}
	if remoteNoWarpDNS.Type != C.DNSTypeHTTPS {
		t.Fatalf("expected remote no-warp DNS type to be %q in TUN mode, got %q", C.DNSTypeHTTPS, remoteNoWarpDNS.Type)
	}
	if dnsOptions.Server != "8.8.8.8" {
		t.Fatalf("expected remote no-warp fallback server to remain 8.8.8.8, got %q", dnsOptions.Server)
	}
}

func TestSetDnsForcesDNSServerDialerResolutionToIPv4WhenIPv6Disabled(t *testing.T) {
	var options option.Options
	staticIPs := map[string][]string{}
	err := setDns(
		&options,
		&HiddifyOptions{
			DNSOptions: DNSOptions{
				RemoteDnsAddress: "https://dns.google/dns-query",
				DirectDnsAddress: "https://dns.alidns.com/dns-query",
			},
			InboundOptions: InboundOptions{
				EnableTun: true,
			},
			RouteOptions: RouteOptions{
				IPv6Mode: option.DomainStrategy(dns.DomainStrategyUseIPv4),
			},
		},
		&staticIPs,
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, tag := range []string{DNSRemoteTag, DNSRemoteTagFallback, DNSTricksDirectTag, DNSDirectTag, DNSRemoteNoWarpTag} {
		server := findTestDNSServer(t, options.DNS.Servers, tag)
		dialer := takeTestDNSServerDialerOptions(t, server)
		if got := dialer.DomainStrategy; got != option.DomainStrategy(dns.DomainStrategyUseIPv4) {
			t.Fatalf("expected DNS server %q dialer strategy to be IPv4-only, got %s", tag, got)
		}
		if dialer.DomainResolver != nil && dialer.DomainResolver.Server != "" {
			if got := dialer.DomainResolver.Strategy; got != option.DomainStrategy(dns.DomainStrategyUseIPv4) {
				t.Fatalf("expected DNS server %q dialer resolver strategy to be IPv4-only, got %s", tag, got)
			}
		}
	}
}

func TestAddForceDirectRoutesOutboundServerDomainsThroughDirectDNS(t *testing.T) {
	options := option.Options{
		Outbounds: []option.Outbound{
			{
				Type: C.TypeVLESS,
				Tag:  "domain-server",
				Options: &option.VLESSOutboundOptions{
					ServerOptions: option.ServerOptions{
						Server:     "proxy.example.com",
						ServerPort: 443,
					},
				},
			},
			{
				Type: C.TypeVLESS,
				Tag:  "ip-server",
				Options: &option.VLESSOutboundOptions{
					ServerOptions: option.ServerOptions{
						Server:     "203.0.113.10",
						ServerPort: 443,
					},
				},
			},
		},
	}

	rules, err := addForceDirect(&options, &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsAddress: "223.5.5.5",
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	matchedServers := []string{}
	for _, rule := range rules {
		if !containsString(rule.RawDefaultDNSRule.Domain, "proxy.example.com") {
			continue
		}
		matchedServers = append(matchedServers, rule.RouteOptions.Server)
		if containsString(rule.RawDefaultDNSRule.Domain, "203.0.113.10") {
			t.Fatal("expected outbound IP literal not to be added as a DNS domain")
		}
	}
	assertDNSRuleServers(t, matchedServers, []string{DNSMultiDirectTag})
}

func findTestDNSServer(t *testing.T, servers []option.DNSServerOptions, tag string) option.DNSServerOptions {
	t.Helper()
	for _, server := range servers {
		if server.Tag == tag {
			return server
		}
	}
	t.Fatalf("expected DNS server %q to be generated", tag)
	return option.DNSServerOptions{}
}

func takeTestDNSServerDialerOptions(t *testing.T, server option.DNSServerOptions) option.DialerOptions {
	t.Helper()
	switch options := server.Options.(type) {
	case *option.RemoteDNSServerOptions:
		return options.DialerOptions
	case *option.RemoteTLSDNSServerOptions:
		return options.DialerOptions
	case *option.RemoteHTTPSDNSServerOptions:
		return options.DialerOptions
	case *option.LocalDNSServerOptions:
		return options.DialerOptions
	default:
		t.Fatalf("unexpected DNS server options for %q: %T", server.Tag, server.Options)
		return option.DialerOptions{}
	}
}

func buildDirectDNSServer(t *testing.T, directDNSAddress string) option.DNSServerOptions {
	t.Helper()

	var options option.Options
	staticIPs := map[string][]string{}
	err := setDns(
		&options,
		&HiddifyOptions{
			DNSOptions: DNSOptions{
				RemoteDnsAddress: "tcp://8.8.8.8",
				DirectDnsAddress: directDNSAddress,
			},
		},
		&staticIPs,
	)
	if err != nil {
		t.Fatal(err)
	}
	if options.DNS == nil {
		t.Fatal("expected DNS options to be set")
	}
	for _, server := range options.DNS.Servers {
		if server.Tag == DNSDirectTag {
			return server
		}
	}
	t.Fatal("expected dns-direct server to be generated")
	return option.DNSServerOptions{}
}

func buildTunDNSServer(t *testing.T, tag string, remoteDNSAddress string, directDNSAddress string) option.DNSServerOptions {
	t.Helper()

	var options option.Options
	staticIPs := map[string][]string{}
	err := setDns(
		&options,
		&HiddifyOptions{
			DNSOptions: DNSOptions{
				RemoteDnsAddress: remoteDNSAddress,
				DirectDnsAddress: directDNSAddress,
			},
			InboundOptions: InboundOptions{
				EnableTun: true,
			},
		},
		&staticIPs,
	)
	if err != nil {
		t.Fatal(err)
	}
	if options.DNS == nil {
		t.Fatal("expected DNS options to be set")
	}
	for _, server := range options.DNS.Servers {
		if server.Tag == tag {
			return server
		}
	}
	t.Fatalf("expected %s server to be generated", tag)
	return option.DNSServerOptions{}
}
