//go:build !windows

package hcore

func newSystemDynamicDirectBypassDNSCacheReader() dynamicDirectBypassDNSCacheReader {
	return nil
}
