package hcore

import (
	"testing"

	"github.com/sagernet/sing-box/option"
	singroute "github.com/sagernet/sing-box/route"
)

func TestApplyRouteConnectionAdmissionLimitsFromCustomOptions(t *testing.T) {
	custom := map[string]any{
		customRouteDirectConnectionLimitKey: 384,
		customRouteProxyConnectionLimitKey:  float64(96),
	}
	defer singroute.SetRouteConnectionAdmissionLimits(
		singroute.DefaultDirectRouteConnectionAdmissionLimit,
		singroute.DefaultProxyRouteConnectionAdmissionLimit,
	)

	directLimit, proxyLimit := applyRouteConnectionAdmissionLimits(option.Options{Custom: &custom})

	if directLimit != 384 || proxyLimit != 96 {
		t.Fatalf("unexpected applied route admission limits: direct=%d proxy=%d", directLimit, proxyLimit)
	}
	appliedDirect, appliedProxy := singroute.RouteConnectionAdmissionLimits()
	if appliedDirect != 384 || appliedProxy != 96 {
		t.Fatalf("unexpected route admission limits: direct=%d proxy=%d", appliedDirect, appliedProxy)
	}
}

func TestApplyRouteConnectionAdmissionLimitsDefaultsInvalidValues(t *testing.T) {
	custom := map[string]any{
		customRouteDirectConnectionLimitKey: 0,
		customRouteProxyConnectionLimitKey:  "invalid",
	}
	defer singroute.SetRouteConnectionAdmissionLimits(
		singroute.DefaultDirectRouteConnectionAdmissionLimit,
		singroute.DefaultProxyRouteConnectionAdmissionLimit,
	)

	directLimit, proxyLimit := applyRouteConnectionAdmissionLimits(option.Options{Custom: &custom})

	if directLimit != singroute.DefaultDirectRouteConnectionAdmissionLimit ||
		proxyLimit != singroute.DefaultProxyRouteConnectionAdmissionLimit {
		t.Fatalf("expected default limits, got direct=%d proxy=%d", directLimit, proxyLimit)
	}
}

func TestApplyRouteConnectionAdmissionLimitsNormalizesLegacyDefaults(t *testing.T) {
	custom := map[string]any{
		customRouteDirectConnectionLimitKey: 512,
		customRouteProxyConnectionLimitKey:  "256",
	}
	defer singroute.SetRouteConnectionAdmissionLimits(
		singroute.DefaultDirectRouteConnectionAdmissionLimit,
		singroute.DefaultProxyRouteConnectionAdmissionLimit,
	)

	directLimit, proxyLimit := applyRouteConnectionAdmissionLimits(option.Options{Custom: &custom})

	if directLimit != singroute.DefaultDirectRouteConnectionAdmissionLimit ||
		proxyLimit != singroute.DefaultProxyRouteConnectionAdmissionLimit {
		t.Fatalf("expected legacy defaults to normalize, got direct=%d proxy=%d", directLimit, proxyLimit)
	}
}
