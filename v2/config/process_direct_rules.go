package config

import (
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func appendProcessDirectRouteRules(routeRules []option.Rule, hopt *HiddifyOptions) []option.Rule {
	if hopt == nil || !hopt.EnableProcessDirectRules {
		return routeRules
	}
	processNames := cleanStringList(hopt.ProcessDirectRuleNames)
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
					Outbound: OutboundDirectTag,
				},
			},
		},
	})
}
