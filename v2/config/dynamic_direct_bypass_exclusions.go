package config

import "strings"

var microsoftUpdateProxyDomainSuffixes = []string{
	"delivery.mp.microsoft.com",
	"emdl.ws.microsoft.com",
	"t-ring.msedge.net",
	"t-ring-s2.msedge.net",
	"c2r.ts.cdn.office.net",
	"windowsupdate.com",
	"delivery.microsoft.com",
	"prod.do.dsp.mp.microsoft.com.edgekey.net",
	"d.akamaiedge.net",
	"dspw65.akamai.net",
	"fg.microsoft.map.fastly.net",
	"bg.microsoft.map.fastly.net",
	"wu-b-net.trafficmanager.net",
	"dcat-b-tlu-net.trafficmanager.net",
	"dcat-f-nlu-net.trafficmanager.net",
	"dcat-f-tlu-net.trafficmanager.net",
	"cdp-f-ssl-tlu-net.trafficmanager.net",
	"tlu.dl.delivery.mp.microsoft.com-c.edgesuite.net",
	"packageretrieval-gthdggdsd6g6bme6.westus2-01.azurewebsites.net",
}

var microsoftStoreCdnProxyDomainSuffixes = []string{
	"cdn.storeedgefd.dsx.mp.microsoft.com",
}

var microsoftStoreControlDirectDomainSuffixes = []string{
	"displaycatalog.mp.microsoft.com",
	"dsp.mp.microsoft.com",
	"storeedge.microsoft.com",
	"storeedgefd.dsx.mp.microsoft.com",
}

var googlePlayProxyDomainSuffixes = []string{
	"xn--ngstr-lra8j.com",
	"gvt1.com",
	"gvt2.com",
	"googleapis.cn",
	"googleapis.com",
	"googleusercontent.com",
	"android.clients.google.com",
	"play.googleapis.com",
	"play-fe.googleapis.com",
	"ggpht.com",
	"googlevideo.com",
}

var claudeProxyDomainSuffixes = []string{
	"anthropic.com",
	"claude.ai",
	"claude.com",
	"claudemcpcontent.com",
}

var localArtifactDomains = []string{
	"local-artifacts.invalid",
}

var forcedProxyDomainSuffixes = mergeDomainSuffixes(
	microsoftUpdateProxyDomainSuffixes,
	microsoftStoreCdnProxyDomainSuffixes,
	googlePlayProxyDomainSuffixes,
	claudeProxyDomainSuffixes,
)

var dynamicDirectBypassExcludedDomainSuffixes = mergeDomainSuffixes(
	forcedProxyDomainSuffixes,
	microsoftStoreControlDirectDomainSuffixes,
)

func MicrosoftUpdateProxyDomainSuffixes() []string {
	return append([]string(nil), microsoftUpdateProxyDomainSuffixes...)
}

func MicrosoftStoreControlDirectDomainSuffixes() []string {
	return append([]string(nil), microsoftStoreControlDirectDomainSuffixes...)
}

func MicrosoftStoreCdnProxyDomainSuffixes() []string {
	return append([]string(nil), microsoftStoreCdnProxyDomainSuffixes...)
}

func GooglePlayProxyDomainSuffixes() []string {
	return append([]string(nil), googlePlayProxyDomainSuffixes...)
}

func ClaudeProxyDomainSuffixes() []string {
	return append([]string(nil), claudeProxyDomainSuffixes...)
}

func LocalArtifactDomains() []string {
	return append([]string(nil), localArtifactDomains...)
}

func ForcedProxyDomainSuffixes() []string {
	return append([]string(nil), forcedProxyDomainSuffixes...)
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

func mergeDomainSuffixes(groups ...[]string) []string {
	var merged []string
	seen := map[string]bool{}
	for _, group := range groups {
		for _, suffix := range group {
			suffix = normalizeDynamicDirectBypassExcludedHost(suffix)
			if suffix == "" || seen[suffix] {
				continue
			}
			seen[suffix] = true
			merged = append(merged, suffix)
		}
	}
	return merged
}
