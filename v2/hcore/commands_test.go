package hcore

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/common/urltest"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type urlTestTargetOutbound struct {
	tag string
}

func (o urlTestTargetOutbound) Type() string           { return "test" }
func (o urlTestTargetOutbound) Tag() string            { return o.tag }
func (o urlTestTargetOutbound) Network() []string      { return []string{N.NetworkTCP, N.NetworkUDP} }
func (o urlTestTargetOutbound) Dependencies() []string { return nil }
func (o urlTestTargetOutbound) DisplayType() string    { return "test" }
func (o urlTestTargetOutbound) IsReady() bool          { return true }
func (o urlTestTargetOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, nil
}
func (o urlTestTargetOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, nil
}

type urlTestTargetGroup struct {
	urlTestTargetOutbound
	now string
	all []string
}

func (g urlTestTargetGroup) Now() string   { return g.now }
func (g urlTestTargetGroup) All() []string { return g.all }

var _ adapter.OutboundGroup = urlTestTargetGroup{}

func TestURLTestTargetForSelectedGroupUsesSelectedLeaf(t *testing.T) {
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory("working-leaf", &adapter.URLTestHistory{
		Delay: 167,
		Time:  time.Now(),
	})

	target := urlTestTargetForSelectedOutbound("lowest", urlTestTargetGroup{
		urlTestTargetOutbound: urlTestTargetOutbound{tag: "lowest"},
		now:                   "working-leaf",
		all:                   []string{"timed-out-leaf", "working-leaf"},
	}, history)

	if target != "working-leaf" {
		t.Fatalf("expected selected group leaf to be URL-tested directly, got %q", target)
	}
}

func TestURLTestTargetForSelectedGroupUsesGroupWhenSelectedLeafHasNoSuccessfulDelay(t *testing.T) {
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory("timed-out-leaf", &adapter.URLTestHistory{
		Delay: monitoring.TimeoutDelay,
		Time:  time.Now(),
	})

	target := urlTestTargetForSelectedOutbound("lowest", urlTestTargetGroup{
		urlTestTargetOutbound: urlTestTargetOutbound{tag: "lowest"},
		now:                   "timed-out-leaf",
		all:                   []string{"timed-out-leaf", "working-leaf"},
	}, history)

	if target != "lowest" {
		t.Fatalf("expected selected group to be URL-tested while leaf delay is invalid, got %q", target)
	}
}

func TestURLTestTargetForSelectedGroupIgnoresCachedLeafDelay(t *testing.T) {
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory("cached-leaf", &adapter.URLTestHistory{
		Delay:       167,
		Time:        time.Now(),
		IsFromCache: true,
	})

	target := urlTestTargetForSelectedOutbound("lowest", urlTestTargetGroup{
		urlTestTargetOutbound: urlTestTargetOutbound{tag: "lowest"},
		now:                   "cached-leaf",
		all:                   []string{"cached-leaf", "working-leaf"},
	}, history)

	if target != "lowest" {
		t.Fatalf("expected selected group to be URL-tested while leaf delay is cached, got %q", target)
	}
}

func TestURLTestTargetForSelectedGroupFallsBackToGroupTag(t *testing.T) {
	target := urlTestTargetForSelectedOutbound("lowest", urlTestTargetGroup{
		urlTestTargetOutbound: urlTestTargetOutbound{tag: "lowest"},
		now:                   "",
		all:                   []string{"timed-out-leaf", "working-leaf"},
	}, nil)

	if target != "lowest" {
		t.Fatalf("expected selected group URL-test target fallback to be the group tag, got %q", target)
	}
}

func TestURLTestTargetForSelectedLeafUsesRealTag(t *testing.T) {
	target := urlTestTargetForSelectedOutbound("proxy-a", urlTestTargetOutbound{tag: "proxy-a"}, nil)

	if target != "proxy-a" {
		t.Fatalf("expected selected leaf to be URL-tested directly, got %q", target)
	}
}
