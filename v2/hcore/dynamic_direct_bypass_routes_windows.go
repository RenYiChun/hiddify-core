//go:build windows

package hcore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const windowsCreateNoWindow = 0x08000000

type windowsDynamicDirectBypassRouteManager struct {
	access       sync.Mutex
	defaultRoute *windowsDefaultRoute
}

type windowsDefaultRoute struct {
	InterfaceIndex int    `json:"InterfaceIndex"`
	NextHop        string `json:"NextHop"`
}

func newSystemDynamicDirectBypassRouteManager() (dynamicDirectBypassRouteManager, error) {
	return &windowsDynamicDirectBypassRouteManager{}, nil
}

func (m *windowsDynamicDirectBypassRouteManager) AddHostRoute(ctx context.Context, addr netip.Addr) error {
	route, err := m.currentDefaultRoute(ctx)
	if err != nil {
		return err
	}
	args := []string{
		addr.String(),
		"MASK", "255.255.255.255",
		route.NextHop,
		"METRIC", "1",
		"IF", strconv.Itoa(route.InterfaceIndex),
	}
	if err := runRouteCommand(ctx, append([]string{"ADD"}, args...)...); err == nil {
		return nil
	}
	if err := runRouteCommand(ctx, append([]string{"CHANGE"}, args...)...); err == nil {
		return nil
	}
	_ = runRouteCommand(ctx, "DELETE", addr.String())
	return runRouteCommand(ctx, append([]string{"ADD"}, args...)...)
}

func (m *windowsDynamicDirectBypassRouteManager) DeleteHostRoute(ctx context.Context, addr netip.Addr) error {
	return runRouteCommand(ctx, "DELETE", addr.String())
}

func (m *windowsDynamicDirectBypassRouteManager) currentDefaultRoute(ctx context.Context) (*windowsDefaultRoute, error) {
	m.access.Lock()
	defer m.access.Unlock()
	if m.defaultRoute != nil {
		return m.defaultRoute, nil
	}
	route, err := discoverWindowsDefaultRoute(ctx)
	if err != nil {
		return nil, err
	}
	m.defaultRoute = route
	return route, nil
}

func discoverWindowsDefaultRoute(ctx context.Context) (*windowsDefaultRoute, error) {
	script := windowsDefaultRouteDiscoveryScript()
	cmd, cancel := newHiddenDynamicDirectBypassCommand(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script)
	defer cancel()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("discover default route failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	output = bytes.TrimSpace(output)
	if len(output) == 0 {
		return nil, fmt.Errorf("no usable physical default route found")
	}
	var route windowsDefaultRoute
	if err := json.Unmarshal(output, &route); err != nil {
		return nil, fmt.Errorf("parse default route failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if route.InterfaceIndex <= 0 || route.NextHop == "" {
		return nil, fmt.Errorf("no usable physical default route found")
	}
	return &route, nil
}

func windowsDefaultRouteDiscoveryScript() string {
	return `$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | ` +
		`Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' -and $_.InterfaceAlias -notmatch 'sing|tun|loopback|vEthernet|Hyper-V|WSL' } | ` +
		`Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1; ` +
		`if (-not $route) { $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | ` +
		`Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 }; ` +
		`if (-not $route) { Write-Error 'no usable physical default route found'; exit 2 }; ` +
		`[pscustomobject]@{ InterfaceIndex = $route.InterfaceIndex; NextHop = $route.NextHop } | ConvertTo-Json -Compress`
}

func runRouteCommand(ctx context.Context, args ...string) error {
	cmd, cancel := newHiddenDynamicDirectBypassCommand(ctx, "route.exe", args...)
	defer cancel()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if output, err := cmd.Output(); err != nil {
		return fmt.Errorf("route %s failed: %w: %s %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)), strings.TrimSpace(stderr.String()))
	}
	return nil
}

func newHiddenDynamicDirectBypassCommand(ctx context.Context, name string, args ...string) (*exec.Cmd, context.CancelFunc) {
	cmdCtx, cancel := dynamicDirectBypassCommandContext(ctx)
	cmd := exec.CommandContext(cmdCtx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windowsCreateNoWindow,
	}
	return cmd, cancel
}

func dynamicDirectBypassCommandContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, 5*time.Second)
}
