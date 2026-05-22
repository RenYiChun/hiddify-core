package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	sdns "github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	"google.golang.org/protobuf/proto"
)

const CustomRouteRulesFileName = "route_rule.proto"

func DefaultRouteRulesPath(basePath string) string {
	return filepath.Join(basePath, CustomRouteRulesFileName)
}

func appendCustomRouteRules(
	dnsRules []option.DefaultDNSRule,
	routeRules []option.Rule,
	hopt *HiddifyOptions,
) ([]option.DefaultDNSRule, []option.Rule, error) {
	rules, err := loadConfiguredRouteRules(hopt)
	if err != nil {
		return dnsRules, routeRules, err
	}
	for _, rule := range rules {
		if rule == nil || !rule.GetEnabled() {
			continue
		}
		if routeRule, ok := makeCustomRouteRule(rule); ok {
			routeRules = append(routeRules, option.Rule{
				Type:           C.RuleTypeDefault,
				DefaultOptions: routeRule,
			})
		}
		if dnsRule, ok := makeCustomDNSRule(rule); ok {
			switch rule.GetOutbound() {
			case Outbound_direct, Outbound_direct_with_fragment:
				dnsRules = appendDirectDNSRules(dnsRules, dnsRule.RawDefaultDNSRule, hopt)
			case Outbound_block:
				rejectRCode := option.DNSRCode(sdns.RcodeRefused)
				dnsRule.DNSRuleAction = option.DNSRuleAction{
					Action: C.RuleActionTypePredefined,
					PredefinedOptions: option.DNSRouteActionPredefined{
						Rcode: &rejectRCode,
					},
				}
				dnsRules = append(dnsRules, dnsRule)
			default:
				dnsRule.DNSRuleAction = option.DNSRuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.DNSRouteActionOptions{
						Server: DNSRemoteTag,
					},
				}
				dnsRules = append(dnsRules, dnsRule)
			}
		}
	}
	return dnsRules, routeRules, nil
}

func loadConfiguredRouteRules(hopt *HiddifyOptions) ([]*Rule, error) {
	if hopt == nil {
		return nil, nil
	}
	rules := make([]*Rule, 0, len(hopt.Rules))
	for i := range hopt.Rules {
		rules = append(rules, &hopt.Rules[i])
	}
	if strings.TrimSpace(hopt.RouteRulesPath) == "" {
		return rules, nil
	}
	fileRules, err := loadRouteRulesFile(hopt.RouteRulesPath)
	if err != nil {
		return rules, nil
	}
	return append(rules, fileRules...), nil
}

func loadRouteRulesFile(path string) ([]*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read custom route rules %q: %w", path, err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var routeRule RouteRule
	if err := proto.Unmarshal(data, &routeRule); err != nil {
		return nil, fmt.Errorf("parse custom route rules %q: %w", path, err)
	}
	return routeRule.GetRules(), nil
}

func makeCustomRouteRule(rule *Rule) (option.DefaultRule, bool) {
	rawRule := option.RawDefaultRule{
		RuleSet:         cleanStringList(rule.GetRuleSets()),
		PackageName:     cleanStringList(rule.GetPackageNames()),
		ProcessName:     cleanStringList(rule.GetProcessNames()),
		ProcessPath:     cleanStringList(rule.GetProcessPaths()),
		PortRange:       cleanStringList(rule.GetPortRanges()),
		SourcePortRange: cleanStringList(rule.GetSourcePortRanges()),
		IPCIDR:          cleanStringList(rule.GetIpCidrs()),
		SourceIPCIDR:    cleanStringList(rule.GetSourceIpCidrs()),
		Domain:          cleanStringList(rule.GetDomains()),
		DomainSuffix:    cleanStringList(rule.GetDomainSuffixes()),
		DomainKeyword:   cleanStringList(rule.GetDomainKeywords()),
		DomainRegex:     cleanStringList(rule.GetDomainRegexes()),
		Protocol:        customRouteRuleProtocols(rule.GetProtocols()),
		Network:         customRouteRuleNetwork(rule.GetNetwork()),
	}
	if !customRouteRuleHasMatchers(rawRule) {
		return option.DefaultRule{}, false
	}
	return option.DefaultRule{
		RawDefaultRule: rawRule,
		RuleAction:     customRouteRuleAction(rule.GetOutbound()),
	}, true
}

func makeCustomDNSRule(rule *Rule) (option.DefaultDNSRule, bool) {
	rawRule := option.RawDefaultDNSRule{
		RuleSet:         cleanStringList(rule.GetRuleSets()),
		PackageName:     cleanStringList(rule.GetPackageNames()),
		ProcessName:     cleanStringList(rule.GetProcessNames()),
		ProcessPath:     cleanStringList(rule.GetProcessPaths()),
		PortRange:       cleanStringList(rule.GetPortRanges()),
		SourcePortRange: cleanStringList(rule.GetSourcePortRanges()),
		IPCIDR:          cleanStringList(rule.GetIpCidrs()),
		SourceIPCIDR:    cleanStringList(rule.GetSourceIpCidrs()),
		Domain:          cleanStringList(rule.GetDomains()),
		DomainSuffix:    cleanStringList(rule.GetDomainSuffixes()),
		DomainKeyword:   cleanStringList(rule.GetDomainKeywords()),
		DomainRegex:     cleanStringList(rule.GetDomainRegexes()),
		Protocol:        customRouteRuleProtocols(rule.GetProtocols()),
		Network:         customRouteRuleNetwork(rule.GetNetwork()),
	}
	if !customDNSRuleHasDomainMatchers(rawRule) {
		return option.DefaultDNSRule{}, false
	}
	return option.DefaultDNSRule{RawDefaultDNSRule: rawRule}, true
}

func customRouteRuleAction(outbound Outbound) option.RuleAction {
	switch outbound {
	case Outbound_direct:
		return option.RuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.RouteActionOptions{
				Outbound: OutboundDirectTag,
			},
		}
	case Outbound_direct_with_fragment:
		return option.RuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.RouteActionOptions{
				Outbound: OutboundDirectFragmentTag,
			},
		}
	case Outbound_block:
		return option.RuleAction{
			Action: C.RuleActionTypeReject,
			RejectOptions: option.RejectActionOptions{
				Method: C.RuleActionRejectMethodDefault,
			},
		}
	default:
		return option.RuleAction{
			Action: C.RuleActionTypeRoute,
			RouteOptions: option.RouteActionOptions{
				Outbound: OutboundMainDetour,
			},
		}
	}
}

func customRouteRuleNetwork(network Network) []string {
	switch network {
	case Network_tcp, Network_udp:
		return []string{network.String()}
	default:
		return nil
	}
}

func customRouteRuleProtocols(protocols []Protocol) []string {
	if len(protocols) == 0 {
		return nil
	}
	values := make([]string, 0, len(protocols))
	seen := map[string]struct{}{}
	for _, protocol := range protocols {
		value := strings.TrimSpace(protocol.String())
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}

func cleanStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cleaned := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		cleaned = append(cleaned, value)
	}
	return cleaned
}

func customRouteRuleHasMatchers(rule option.RawDefaultRule) bool {
	return !reflect.DeepEqual(rule, option.RawDefaultRule{})
}

func customDNSRuleHasDomainMatchers(rule option.RawDefaultDNSRule) bool {
	return len(rule.RuleSet) > 0 ||
		len(rule.Domain) > 0 ||
		len(rule.DomainSuffix) > 0 ||
		len(rule.DomainKeyword) > 0 ||
		len(rule.DomainRegex) > 0
}
