package config

import (
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

var defaultProcessStableProxyExcludedKeywords = []string{"naive", "quic", "tuic"}

func newProcessStableProxyOutbound(tags []string, hopt *HiddifyOptions) *option.Outbound {
	if len(processStableProxyRuleNames(hopt)) == 0 {
		return nil
	}
	stableTags := filterProcessStableProxyOutbounds(tags, processStableProxyExcludedKeywords(hopt))
	if len(stableTags) == 0 {
		return nil
	}
	return &option.Outbound{
		Type: C.TypeBalancer,
		Tag:  OutboundProcessStableProxyTag,
		Options: &option.BalancerOutboundOptions{
			Outbounds:                 stableTags,
			Strategy:                  "lowest-delay",
			DelayAcceptableRatio:      2,
			Tolerance:                 1,
			InterruptExistConnections: false,
		},
	}
}

func appendProcessStableProxyRouteRules(routeRules []option.Rule, hopt *HiddifyOptions) []option.Rule {
	processNames := processStableProxyRuleNames(hopt)
	if len(processNames) == 0 {
		return routeRules
	}
	return append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				ProcessName: processNames,
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: OutboundProcessStableProxyTag,
				},
			},
		},
	})
}

func processStableProxyRuleNames(hopt *HiddifyOptions) []string {
	if hopt == nil || !hopt.EnableProcessStableProxyRules {
		return nil
	}
	return cleanStringList(hopt.ProcessStableProxyRuleNames)
}

func processStableProxyExcludedKeywords(hopt *HiddifyOptions) []string {
	var values []string
	if hopt != nil {
		values = cleanStringList(hopt.ProcessStableProxyExcludedKeywords)
	}
	if len(values) == 0 {
		values = defaultProcessStableProxyExcludedKeywords
	}
	keywords := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		keyword := strings.ToLower(strings.TrimSpace(value))
		if keyword == "" {
			continue
		}
		if _, ok := seen[keyword]; ok {
			continue
		}
		seen[keyword] = struct{}{}
		keywords = append(keywords, keyword)
	}
	return keywords
}

func filterProcessStableProxyOutbounds(tags []string, excludedKeywords []string) []string {
	if len(tags) == 0 {
		return nil
	}
	stableTags := make([]string, 0, len(tags))
	for _, tag := range tags {
		normalizedTag := strings.ToLower(tag)
		excluded := false
		for _, keyword := range excludedKeywords {
			if strings.Contains(normalizedTag, keyword) {
				excluded = true
				break
			}
		}
		if !excluded {
			stableTags = append(stableTags, tag)
		}
	}
	return stableTags
}

func processStableProxyDiagnosticOutbounds(options *option.Options, hopt *HiddifyOptions) ([]string, []string) {
	if options == nil {
		return nil, nil
	}
	candidates := processStableProxyCandidateOutbounds(options)
	if len(candidates) == 0 {
		return nil, nil
	}
	excludedKeywords := processStableProxyExcludedKeywords(hopt)
	excluded := make([]string, 0)
	candidateSet := make(map[string]struct{}, len(candidates))
	for _, tag := range candidates {
		candidateSet[tag] = struct{}{}
	}
	for _, outbound := range options.Outbounds {
		tag := strings.TrimSpace(outbound.Tag)
		if tag == "" {
			continue
		}
		if _, ok := candidateSet[tag]; ok {
			continue
		}
		if containsPredefinedOutboundTag(tag) {
			continue
		}
		if len(filterProcessStableProxyOutbounds([]string{tag}, excludedKeywords)) == 0 {
			excluded = append(excluded, tag)
		}
	}
	return candidates, cleanStringList(excluded)
}

func processStableProxyCandidateOutbounds(options *option.Options) []string {
	if options == nil {
		return nil
	}
	for _, outbound := range options.Outbounds {
		if outbound.Tag != OutboundProcessStableProxyTag {
			continue
		}
		if balancerOptions, ok := outbound.Options.(*option.BalancerOutboundOptions); ok {
			return cleanStringList(balancerOptions.Outbounds)
		}
	}
	return nil
}

func containsPredefinedOutboundTag(tag string) bool {
	for _, predefinedTag := range PredefinedOutboundTags {
		if tag == predefinedTag {
			return true
		}
	}
	return false
}
