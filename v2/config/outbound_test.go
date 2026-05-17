package config

import (
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestSetOutboundsDefaultsSelectorToLowestDelay(t *testing.T) {
	var options option.Options
	staticIPs := map[string][]string{}
	input := &option.Options{
		Outbounds: []option.Outbound{
			{
				Type:    C.TypeDirect,
				Tag:     "proxy-a",
				Options: &option.DirectOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "proxy-b",
				Options: &option.DirectOutboundOptions{},
			},
		},
	}

	if err := setOutbounds(&options, input, &HiddifyOptions{}, &staticIPs); err != nil {
		t.Fatal(err)
	}

	for _, outbound := range options.Outbounds {
		if outbound.Tag != OutboundSelectTag {
			continue
		}
		selectorOptions, ok := outbound.Options.(*option.SelectorOutboundOptions)
		if !ok {
			t.Fatalf("expected selector options, got %T", outbound.Options)
		}
		if selectorOptions.Default != OutboundURLTestTag {
			t.Fatalf("expected selector default to be %q, got %q", OutboundURLTestTag, selectorOptions.Default)
		}
		return
	}
	t.Fatal("expected selector outbound to be generated")
}

func TestSetOutboundsDefaultsBalanceStrategy(t *testing.T) {
	var options option.Options
	staticIPs := map[string][]string{}
	input := &option.Options{
		Outbounds: []option.Outbound{
			{
				Type:    C.TypeDirect,
				Tag:     "proxy-a",
				Options: &option.DirectOutboundOptions{},
			},
			{
				Type:    C.TypeDirect,
				Tag:     "proxy-b",
				Options: &option.DirectOutboundOptions{},
			},
		},
	}

	if err := setOutbounds(&options, input, &HiddifyOptions{}, &staticIPs); err != nil {
		t.Fatal(err)
	}

	for _, outbound := range options.Outbounds {
		if outbound.Tag != OutboundRoundRobinTag {
			continue
		}
		balancerOptions, ok := outbound.Options.(*option.BalancerOutboundOptions)
		if !ok {
			t.Fatalf("expected balancer options, got %T", outbound.Options)
		}
		if balancerOptions.Strategy != "round-robin" {
			t.Fatalf("expected balance strategy to default to %q, got %q", "round-robin", balancerOptions.Strategy)
		}
		return
	}
	t.Fatal("expected balance outbound to be generated")
}

func TestSetOutboundsAddsDirectConnectTimeouts(t *testing.T) {
	var options option.Options
	staticIPs := map[string][]string{}
	input := &option.Options{
		Outbounds: []option.Outbound{
			{
				Type:    C.TypeDirect,
				Tag:     "proxy-a",
				Options: &option.DirectOutboundOptions{},
			},
		},
	}

	if err := setOutbounds(&options, input, &HiddifyOptions{}, &staticIPs); err != nil {
		t.Fatal(err)
	}

	found := map[string]bool{}
	for _, outbound := range options.Outbounds {
		if outbound.Tag != OutboundDirectTag && outbound.Tag != OutboundDirectFragmentTag {
			continue
		}
		found[outbound.Tag] = true
		directOptions, ok := outbound.Options.(*option.DirectOutboundOptions)
		if !ok {
			t.Fatalf("expected direct outbound options for %q, got %T", outbound.Tag, outbound.Options)
		}
		if got := time.Duration(directOptions.ConnectTimeout); got != 3*time.Second {
			t.Fatalf("expected %q connect timeout to be 3s, got %s", outbound.Tag, got)
		}
	}
	for _, tag := range []string{OutboundDirectTag, OutboundDirectFragmentTag} {
		if !found[tag] {
			t.Fatalf("expected %q outbound to be generated", tag)
		}
	}
}
