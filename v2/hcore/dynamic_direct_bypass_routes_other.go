//go:build !windows

package hcore

import "fmt"

func newSystemDynamicDirectBypassRouteManager() (dynamicDirectBypassRouteManager, error) {
	return nil, fmt.Errorf("dynamic direct bypass route manager is only available on windows")
}
