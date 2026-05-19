//go:build windows

package hcore

import (
	"errors"

	"github.com/sagernet/sing/common/wininet"
	"golang.org/x/sys/windows/registry"
)

const windowsInternetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func currentWindowsSystemProxyState() (windowsSystemProxyState, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, windowsInternetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return windowsSystemProxyState{}, err
	}
	defer key.Close()

	enabled, _, err := key.GetIntegerValue("ProxyEnable")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return windowsSystemProxyState{}, err
	}
	server, _, err := key.GetStringValue("ProxyServer")
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return windowsSystemProxyState{}, err
	}
	return windowsSystemProxyState{
		enabled: enabled != 0,
		server:  server,
	}, nil
}

func clearWindowsSystemProxy() error {
	return wininet.ClearSystemProxy()
}
