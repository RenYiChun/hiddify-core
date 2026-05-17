package config

import (
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	dns "github.com/sagernet/sing-dns"
)

func TestSetInboundExcludesDirectDNSIPFromTunRoutes(t *testing.T) {
	tunOptions := buildTunInbound(t, "https://223.5.5.5/dns-query")

	if !hasRouteExclude(tunOptions.RouteExcludeAddress, "223.5.5.5/32") {
		t.Fatalf("expected direct DNS IP to be excluded from TUN routes, got %v", tunOptions.RouteExcludeAddress)
	}
}

func TestSetInboundExcludesConfiguredDirectDNSIPFromTunRoutes(t *testing.T) {
	tunOptions := buildTunInbound(t, "tcp://1.1.1.1")

	if !hasRouteExclude(tunOptions.RouteExcludeAddress, "1.1.1.1/32") {
		t.Fatalf("expected configured direct DNS IP to be excluded from TUN routes, got %v", tunOptions.RouteExcludeAddress)
	}
}

func TestSetInboundDoesNotExcludeDomainDirectDNSFromTunRoutes(t *testing.T) {
	tunOptions := buildTunInbound(t, "https://dns.alidns.com/dns-query")

	if len(tunOptions.RouteExcludeAddress) != 0 {
		t.Fatalf("expected domain direct DNS not to add route excludes, got %v", tunOptions.RouteExcludeAddress)
	}
}

func TestSetInboundExcludesOutboundServerIPsFromTunRoutes(t *testing.T) {
	tunOptions := buildTunInboundWithOutbounds(t, "https://dns.alidns.com/dns-query", []option.Outbound{
		{
			Type: C.TypeVLESS,
			Tag:  "ip-server",
			Options: &option.VLESSOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     "209.87.93.20",
					ServerPort: 443,
				},
			},
		},
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
	})

	if !hasRouteExclude(tunOptions.RouteExcludeAddress, "209.87.93.20/32") {
		t.Fatalf("expected outbound server IP to be excluded from TUN routes, got %v", tunOptions.RouteExcludeAddress)
	}
}

func TestSetInboundOmitsIPv6AddressWhenIPv6ModeIsIPv4Only(t *testing.T) {
	tunOptions := buildTunInboundWithIPv6Mode(t, "https://223.5.5.5/dns-query", option.DomainStrategy(dns.DomainStrategyUseIPv4))

	for _, address := range tunOptions.Address {
		if address.Addr().Is6() {
			t.Fatalf("expected IPv4-only mode not to configure IPv6 TUN address, got %v", tunOptions.Address)
		}
	}
}

func TestSetInboundKeepsIPv6AddressWhenIPv6ModeAllowsIPv6(t *testing.T) {
	tunOptions := buildTunInboundWithIPv6Mode(t, "https://223.5.5.5/dns-query", option.DomainStrategy(dns.DomainStrategyAsIS))

	if !hasIPv6Prefix(tunOptions.Address) && isIPv6Supported() {
		t.Fatalf("expected IPv6-capable host to keep IPv6 TUN address, got %v", tunOptions.Address)
	}
}

func buildTunInbound(t *testing.T, directDNSAddress string) *option.TunInboundOptions {
	t.Helper()

	return buildTunInboundWithIPv6Mode(t, directDNSAddress, option.DomainStrategy(dns.DomainStrategyAsIS))
}

func buildTunInboundWithIPv6Mode(t *testing.T, directDNSAddress string, ipv6Mode option.DomainStrategy) *option.TunInboundOptions {
	t.Helper()

	var options option.Options
	setInbound(
		&options,
		&HiddifyOptions{
			DNSOptions: DNSOptions{
				DirectDnsAddress: directDNSAddress,
			},
			InboundOptions: InboundOptions{
				EnableTun: true,
				TUNStack:  "mixed",
				MTU:       9000,
			},
			RouteOptions: RouteOptions{
				IPv6Mode: ipv6Mode,
			},
		},
	)
	setTunRouteExcludes(
		&options,
		&HiddifyOptions{
			DNSOptions: DNSOptions{
				DirectDnsAddress: directDNSAddress,
			},
			InboundOptions: InboundOptions{
				EnableTun: true,
			},
		},
	)
	return findTunInbound(t, &options)
}

func buildTunInboundWithOutbounds(t *testing.T, directDNSAddress string, outbounds []option.Outbound) *option.TunInboundOptions {
	t.Helper()

	var options option.Options
	hopt := &HiddifyOptions{
		DNSOptions: DNSOptions{
			DirectDnsAddress: directDNSAddress,
		},
		InboundOptions: InboundOptions{
			EnableTun: true,
			TUNStack:  "mixed",
			MTU:       9000,
		},
	}
	setInbound(&options, hopt)
	staticIPs := map[string][]string{}
	if err := setOutbounds(&options, &option.Options{Outbounds: outbounds}, hopt, &staticIPs); err != nil {
		t.Fatal(err)
	}
	setTunRouteExcludes(&options, hopt)
	return findTunInbound(t, &options)
}

func findTunInbound(t *testing.T, options *option.Options) *option.TunInboundOptions {
	t.Helper()

	for _, inbound := range options.Inbounds {
		if inbound.Tag != InboundTUNTag {
			continue
		}
		tunOptions, ok := inbound.Options.(*option.TunInboundOptions)
		if !ok {
			t.Fatalf("expected TUN inbound options, got %T", inbound.Options)
		}
		return tunOptions
	}
	t.Fatal("expected TUN inbound to be generated")
	return nil
}

func hasRouteExclude(prefixes []netip.Prefix, expected string) bool {
	expectedPrefix := netip.MustParsePrefix(expected)
	for _, prefix := range prefixes {
		if prefix == expectedPrefix {
			return true
		}
	}
	return false
}

func hasIPv6Prefix(prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Addr().Is6() {
			return true
		}
	}
	return false
}
