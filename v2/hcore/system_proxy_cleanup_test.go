package hcore

import (
	"net/netip"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func TestShouldClearStaleSystemProxyForTunClearsLocalMixedProxy(t *testing.T) {
	options := tunOptionsWithMixedProxy(t, false)
	state := windowsSystemProxyState{
		enabled: true,
		server:  "http://127.0.0.1:12334",
	}

	if !shouldClearStaleSystemProxyForTun(options, state) {
		t.Fatal("expected stale Hiddify system proxy to be cleared in TUN mode")
	}
}

func TestShouldClearStaleSystemProxyForTunPreservesEnabledSystemProxyMode(t *testing.T) {
	options := tunOptionsWithMixedProxy(t, true)
	state := windowsSystemProxyState{
		enabled: true,
		server:  "http://127.0.0.1:12334",
	}

	if shouldClearStaleSystemProxyForTun(options, state) {
		t.Fatal("expected active system proxy mode not to be cleared")
	}
}

func TestShouldClearStaleSystemProxyForTunPreservesUserProxy(t *testing.T) {
	options := tunOptionsWithMixedProxy(t, false)
	state := windowsSystemProxyState{
		enabled: true,
		server:  "http://127.0.0.1:8888",
	}

	if shouldClearStaleSystemProxyForTun(options, state) {
		t.Fatal("expected unrelated user proxy not to be cleared")
	}
}

func TestShouldClearStaleSystemProxyForTunIgnoresNonTun(t *testing.T) {
	options := tunOptionsWithMixedProxy(t, false)
	options.Inbounds = options.Inbounds[1:]
	state := windowsSystemProxyState{
		enabled: true,
		server:  "http://127.0.0.1:12334",
	}

	if shouldClearStaleSystemProxyForTun(options, state) {
		t.Fatal("expected non-TUN mode not to clear system proxy")
	}
}

func tunOptionsWithMixedProxy(t *testing.T, setSystemProxy bool) option.Options {
	t.Helper()
	addr := badoption.Addr(netip.MustParseAddr("127.0.0.1"))
	return option.Options{
		Inbounds: []option.Inbound{
			{
				Type: C.TypeTun,
				Tag:  "tun-in",
			},
			{
				Type: C.TypeMixed,
				Tag:  "mixed-in127.0.0.1",
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     &addr,
						ListenPort: 12334,
					},
					SetSystemProxy: setSystemProxy,
				},
			},
		},
	}
}
