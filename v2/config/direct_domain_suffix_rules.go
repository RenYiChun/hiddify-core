package config

import (
	"os"
	"path/filepath"
	"strings"
)

const DirectDomainSuffixRulesRelativePath = "rules/direct-domain-suffixes.txt"

func DefaultDirectDomainSuffixRulesPath(basePath string) string {
	return filepath.Join(basePath, DirectDomainSuffixRulesRelativePath)
}

func DefaultDirectDomainSuffixRules() []string {
	return normalizeDirectDomainSuffixRules(defaultDirectDomainSuffixRules)
}

func LoadDirectDomainSuffixRulesFile(path string, defaults []string) ([]string, error) {
	if path == "" {
		return normalizeDirectDomainSuffixRules(defaults), nil
	}
	if _, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(formatDirectDomainSuffixRulesFile(defaults)), 0o644); err != nil {
			return nil, err
		}
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseDirectDomainSuffixRules(string(content)), nil
}

func ParseDirectDomainSuffixRules(content string) []string {
	return normalizeDirectDomainSuffixRules(strings.Split(content, "\n"))
}

func configuredDirectDomainSuffixRules(hopt *HiddifyOptions) []string {
	defaults := DefaultDirectDomainSuffixRules()
	if hopt == nil || hopt.DirectDomainSuffixRulesPath == "" {
		return defaults
	}
	suffixes, err := LoadDirectDomainSuffixRulesFile(hopt.DirectDomainSuffixRulesPath, defaults)
	if err != nil {
		return defaults
	}
	return suffixes
}

func formatDirectDomainSuffixRulesFile(defaults []string) string {
	var builder strings.Builder
	builder.WriteString("# Hiddify direct domain suffix rules\n")
	builder.WriteString("# One domain suffix per line. Blank lines and lines beginning with # are ignored.\n")
	builder.WriteString("# Matching domains use direct DNS and direct route when the generated config starts.\n\n")
	for _, suffix := range normalizeDirectDomainSuffixRules(defaults) {
		builder.WriteString(suffix)
		builder.WriteByte('\n')
	}
	return builder.String()
}

func normalizeDirectDomainSuffixRules(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		suffix, ok := normalizeDirectDomainSuffixRule(value)
		if !ok {
			continue
		}
		if _, exists := seen[suffix]; exists {
			continue
		}
		seen[suffix] = struct{}{}
		result = append(result, suffix)
	}
	return result
}

func normalizeDirectDomainSuffixRule(value string) (string, bool) {
	value = strings.TrimSpace(strings.TrimPrefix(value, "\ufeff"))
	if commentIndex := strings.Index(value, "#"); commentIndex >= 0 {
		value = strings.TrimSpace(value[:commentIndex])
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	value = strings.TrimPrefix(value, "*.")
	if value == "" || strings.ContainsAny(value, "/\\: \t\r\n") {
		return "", false
	}
	labelsText := strings.TrimPrefix(value, ".")
	if labelsText == "" || strings.Contains(labelsText, "..") {
		return "", false
	}
	if !strings.HasPrefix(value, ".") && !strings.Contains(labelsText, ".") {
		return "", false
	}
	for _, label := range strings.Split(labelsText, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", false
		}
		for _, ch := range label {
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return "", false
		}
	}
	return value, true
}
