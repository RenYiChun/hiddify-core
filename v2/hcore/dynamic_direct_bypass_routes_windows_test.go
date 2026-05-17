//go:build windows

package hcore

import (
	"context"
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
