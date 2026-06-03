package config

import "strings"

var microsoftUpdateProxyDomainSuffixes = []string{
	"delivery.mp.microsoft.com",
	"displaycatalog.mp.microsoft.com",
	"dsp.mp.microsoft.com",
	"emdl.ws.microsoft.com",
	"storeedgefd.dsx.mp.microsoft.com",
	"t-ring.msedge.net",
	"t-ring-s2.msedge.net",
	"c2r.ts.cdn.office.net",
	"windowsupdate.com",
}

var dynamicDirectBypassExcludedDomainSuffixes = microsoftUpdateProxyDomainSuffixes

func MicrosoftUpdateProxyDomainSuffixes() []string {
	return append([]string(nil), microsoftUpdateProxyDomainSuffixes...)
}

func IsDynamicDirectBypassExcludedHost(host string) bool {
	host = normalizeDynamicDirectBypassExcludedHost(host)
	if host == "" {
		return false
	}
	for _, suffix := range dynamicDirectBypassExcludedDomainSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func normalizeDynamicDirectBypassExcludedHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	return strings.TrimSuffix(host, ".")
}
