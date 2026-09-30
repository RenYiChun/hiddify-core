package config

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/batch"
	SJ "github.com/sagernet/sing/common/json"
	"github.com/xmdhs/clash2singbox/convert"
	clash2singmodel "github.com/xmdhs/clash2singbox/model"
	"github.com/xmdhs/clash2singbox/model/clash"
	"gopkg.in/yaml.v3"
)

//go:embed config.json.template
var configByte []byte

func ReadContent(ctx context.Context, opt *ReadOptions) ([]byte, error) {
	if opt.Content == "" {
		contentBytes, err := os.ReadFile(opt.Path)
		if err != nil {
			return nil, err
		}
		opt.Content = string(contentBytes)
	}
	return []byte(opt.Content), nil
}

func ParseConfig(ctx context.Context, opt *ReadOptions, debug bool, configOpt *HiddifyOptions, fullConfig bool) (*option.Options, error) {
	content, err := ReadContent(ctx, opt)
	if err != nil {
		return nil, err
	}
	return parseConfigContent(ctx, content, debug, nil, false)
}

func ParseConfigBytes(ctx context.Context, opt *ReadOptions, debug bool, configOpt *HiddifyOptions, fullConfig bool) ([]byte, error) {

	options, err := ParseConfig(ctx, opt, debug, configOpt, fullConfig)
	if err != nil {
		return nil, err
	}

	return options.MarshalJSONContext(ctx)

}
func parseConfigContent(ctx context.Context, content []byte, debug bool, configOpt *HiddifyOptions, fullConfig bool) (*option.Options, error) {
	if configOpt == nil {
		configOpt = DefaultHiddifyOptions()
	}

	var jsonObj map[string]interface{} = make(map[string]interface{})

	var tmpJsonResult any
	jsonDecoder := json.NewDecoder(SJ.NewCommentFilter(bytes.NewReader(content)))
	if err := jsonDecoder.Decode(&tmpJsonResult); err == nil {
		fmt.Printf("Convert using json\n")
		if tmpJsonObj, ok := tmpJsonResult.(map[string]interface{}); ok {
			if tmpJsonObj["outbounds"] == nil && tmpJsonObj["endpoints"] == nil {
				jsonObj["outbounds"] = []interface{}{jsonObj}
			} else {
				if fullConfig || (configOpt != nil && configOpt.EnableFullConfig) {
					jsonObj = tmpJsonObj
				} else {
					if tmpJsonObj["outbounds"] != nil {
						jsonObj["outbounds"] = tmpJsonObj["outbounds"]
					}
					if tmpJsonObj["endpoints"] != nil {
						jsonObj["endpoints"] = tmpJsonObj["endpoints"]
					}
				}
			}
		} else if jsonArray, ok := tmpJsonResult.([]map[string]interface{}); ok {
			jsonObj["outbounds"] = jsonArray
		} else {
			return nil, fmt.Errorf("[SingboxParser] Incorrect Json Format")
		}

		newContent, _ := json.MarshalIndent(jsonObj, "", "  ")

		return patchConfigStr(ctx, newContent, "SingboxParser", configOpt)
	}

	fmt.Printf("Convert using clash\n")
	clashObj := clash.Clash{}
	if err := yaml.Unmarshal(content, &clashObj); err == nil && clashObj.Proxies != nil {
		if len(clashObj.Proxies) == 0 {
			return nil, fmt.Errorf("[ClashParser] no outbounds found")
		}
		converted, endpoints, err := convert.Clash2sing(clashObj, clash2singmodel.SINGLATEST)
		if err != nil {
			return nil, fmt.Errorf("[ClashParser] converting clash to sing-box error: %w", err)
		}
		output := configByte
		output, err = convert.Patch(output, converted, endpoints, "", "", nil)
		if err != nil {
			return nil, fmt.Errorf("[ClashParser] patching clash config error: %w", err)
		}
		return patchConfigStr(ctx, output, "ClashParser", configOpt)
	}

	v2ray, err := ray2sing.Ray2SingboxOptions(ctx, string(content), configOpt.UseXrayCoreWhenPossible)
	if err == nil {
		return patchConfigOptions(ctx, v2ray, "V2rayParser", configOpt)
	}

	return nil, fmt.Errorf("unable to determine config format")
}

func patchConfigStr(ctx context.Context, content []byte, name string, configOpt *HiddifyOptions) (*option.Options, error) {
	content = migrateLegacyDNSOutbound(content)
	options := option.Options{}
	err := options.UnmarshalJSONContext(ctx, content)

	if err != nil {
		return nil, fmt.Errorf("[SingboxParser] unmarshal error: %w", err)
	}

	return patchConfigOptions(ctx, &options, name, configOpt)
}
func patchConfigOptions(ctx context.Context, options *option.Options, name string, configOpt *HiddifyOptions) (*option.Options, error) {
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[*option.Endpoint](2))
	for _, base := range options.Endpoints {
		out := base
		b.Go(base.Tag, func() (*option.Endpoint, error) {
			err := patchWarp(&out, configOpt, false, nil)
			if err != nil {
				return nil, fmt.Errorf("[Warp] patch warp error: %w", err)
			}
			// options.Outbounds[i] = base
			return &out, nil
		})
	}
	if res, err := b.WaitAndGetResult(); err != nil {
		return nil, err
	} else {
		for i, base := range options.Endpoints {
			options.Endpoints[i] = *res[base.Tag].Value
		}
	}

	// fmt.Printf("%s\n", content)
	return validateResult(ctx, options, name)
}

func validateResult(ctx context.Context, options *option.Options, name string) (*option.Options, error) {
	err := libbox.CheckConfigOptions(options)
	if err != nil {
		return nil, fmt.Errorf("[%s] invalid sing-box config: %w", name, err)
	}
	return options, nil
}

// migrateLegacyDNSOutbound migrates legacy configs that still use the `dns`
// outbound (deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0).
// The legacy dns outbound entries are removed and every route rule pointing
// to one is rewritten into the equivalent rule action ("hijack-dns"), following
// https://sing-box.sagernet.org/migration/#migrate-legacy-special-outbounds-to-rule-actions.
// Content without legacy dns outbounds is returned unchanged.
func migrateLegacyDNSOutbound(content []byte) []byte {
	var obj map[string]any
	if err := json.Unmarshal(content, &obj); err != nil {
		return content
	}

	rawOutbounds, ok := obj["outbounds"].([]any)
	if !ok {
		return content
	}

	dnsTags := make(map[string]bool)
	kept := rawOutbounds[:0]
	removed := false
	for _, rawOutbound := range rawOutbounds {
		outbound, ok := rawOutbound.(map[string]any)
		if !ok || outbound["type"] != "dns" {
			kept = append(kept, rawOutbound)
			continue
		}
		removed = true
		if tag, ok := outbound["tag"].(string); ok && tag != "" {
			dnsTags[tag] = true
		}
	}
	if !removed {
		return content
	}
	obj["outbounds"] = kept

	if route, ok := obj["route"].(map[string]any); ok {
		if rules, ok := route["rules"].([]any); ok {
			for _, rawRule := range rules {
				rule, ok := rawRule.(map[string]any)
				if !ok {
					continue
				}
				if outboundTag, ok := rule["outbound"].(string); ok && dnsTags[outboundTag] {
					delete(rule, "outbound")
					rule["action"] = "hijack-dns"
				}
			}
		}
		if finalTag, ok := route["final"].(string); ok && dnsTags[finalTag] {
			delete(route, "final")
		}
	}

	for _, rawOutbound := range kept {
		outbound, ok := rawOutbound.(map[string]any)
		if !ok {
			continue
		}
		if group, ok := outbound["outbounds"].([]any); ok {
			filtered := group[:0]
			for _, rawTag := range group {
				if tag, ok := rawTag.(string); ok && dnsTags[tag] {
					continue
				}
				filtered = append(filtered, rawTag)
			}
			outbound["outbounds"] = filtered
		}
	}

	migrated, err := json.Marshal(obj)
	if err != nil {
		return content
	}
	return migrated
}
