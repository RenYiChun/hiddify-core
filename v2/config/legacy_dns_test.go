package config

import (
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
)

func TestMigrateLegacyDNSOutboundWithoutTag(t *testing.T) {
	content := []byte(`{"outbounds":[{"type":"direct","tag":"direct"},{"type":"dns"}]}`)
	migrated := migrateLegacyDNSOutbound(content)
	var result struct {
		Outbounds []struct {
			Type string `json:"type"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(migrated, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Outbounds) != 1 || result.Outbounds[0].Type != "direct" {
		t.Fatalf("untagged DNS outbound was not removed: %s", migrated)
	}

	if _, err := ParseConfig(libbox.BaseContext(nil), &ReadOptions{Content: string(content)}, false, nil, false); err != nil {
		t.Fatalf("profile parser rejected legacy DNS outbound: %v", err)
	}
}

func TestReadSingOptionsMigratesLegacyDNSOutbound(t *testing.T) {
	content := `{"outbounds":[{"type":"direct","tag":"direct"},{"type":"dns","tag":"dns-out"}],"route":{"rules":[{"protocol":"dns","outbound":"dns-out"}]}}`
	options, err := ReadSingOptions(libbox.BaseContext(nil), &ReadOptions{Content: content})
	if err != nil {
		t.Fatalf("config reader rejected legacy DNS outbound: %v", err)
	}
	if len(options.Outbounds) != 1 || options.Outbounds[0].Type != "direct" {
		t.Fatalf("expected only the direct outbound, got %d", len(options.Outbounds))
	}
	encoded, err := options.MarshalJSONContext(libbox.BaseContext(nil))
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Route struct {
			Rules []struct {
				Action   string `json:"action"`
				Outbound string `json:"outbound"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Route.Rules) != 1 || result.Route.Rules[0].Action != "hijack-dns" || result.Route.Rules[0].Outbound != "" {
		t.Fatalf("DNS route rule was not migrated: %s", encoded)
	}
}
