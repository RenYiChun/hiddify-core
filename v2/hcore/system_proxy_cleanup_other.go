//go:build !windows

package hcore

func currentWindowsSystemProxyState() (windowsSystemProxyState, error) {
	return windowsSystemProxyState{}, nil
}

func clearWindowsSystemProxy() error {
	return nil
}
