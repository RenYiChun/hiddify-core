//go:build windows

package hcore

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestNewHiddenDynamicDirectBypassCommandHidesChildWindow(t *testing.T) {
	cmd, cancel := newHiddenDynamicDirectBypassCommand(context.Background(), "cmd.exe", "/c", "exit", "0")
	defer cancel()

	if cmd.SysProcAttr == nil {
		t.Fatal("expected child process SysProcAttr to be set")
	}
	if !cmd.SysProcAttr.HideWindow {
		t.Fatal("expected child process window to be hidden")
	}
	if cmd.SysProcAttr.CreationFlags&windowsCreateNoWindow == 0 {
		t.Fatalf("expected CREATE_NO_WINDOW flag, got %#x", cmd.SysProcAttr.CreationFlags)
	}
}

func TestWindowsDefaultRouteDiscoveryScriptOutputsJson(t *testing.T) {
	script := strings.TrimSpace(windowsDefaultRouteDiscoveryScript())
	if !strings.Contains(script, "ConvertTo-Json -Compress") {
		t.Fatalf("expected discovery script to convert selected route to JSON: %s", script)
	}
	if !strings.Contains(script, "[pscustomobject]") {
		t.Fatalf("expected discovery script to explicitly write route JSON to stdout: %s", script)
	}
	if !strings.Contains(script, "Write-Error") {
		t.Fatalf("expected discovery script to fail explicitly when no route is found: %s", script)
	}
}

func TestWindowsRouteBatchScriptReadsJSONInputAsIndividualIPs(t *testing.T) {
	route := &windowsDefaultRoute{InterfaceIndex: 1, NextHop: "192.0.2.1"}
	script := windowsAddHostRoutesScript(route)
	cutoff := strings.Index(script, "try {")
	if cutoff < 0 {
		t.Fatal("expected add route script to contain a route mutation block")
	}
	script = script[:cutoff] + `
$failures = @()
foreach ($ip in $ips) {
  $failures += [pscustomobject]@{ ip = $ip; error = "probe $ip" }
}
if ($failures.Count -eq 0) { '[]' } else { ConvertTo-Json -Compress -InputObject @($failures) }`

	addrs := []netip.Addr{
		netip.MustParseAddr("49.79.227.133"),
		netip.MustParseAddr("49.79.227.198"),
	}
	failures := runWindowsRouteBatchCommand(context.Background(), "test", script, addrs)

	if len(failures) != len(addrs) {
		t.Fatalf("expected one parsed failure per IP, got %#v", failures)
	}
	for _, addr := range addrs {
		err := failures[addr]
		if err == nil || !strings.Contains(err.Error(), "probe "+addr.String()) {
			t.Fatalf("expected parsed failure for %s, got %#v", addr, err)
		}
	}
}
