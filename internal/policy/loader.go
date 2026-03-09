package policy

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Load はファイルパスからポリシーを読み込む。
func Load(path string) (*PolicyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse はバイト列からポリシーをパースし、バリデーションする。
func Parse(data []byte) (*PolicyFile, error) {
	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}
	if err := validate(&pf); err != nil {
		return nil, err
	}
	return &pf, nil
}

func validate(pf *PolicyFile) error {
	if pf.Version != "v1" {
		return fmt.Errorf("policy: unsupported version %q (expected \"v1\")", pf.Version)
	}
	if pf.Mode != "enforce" && pf.Mode != "audit" {
		return fmt.Errorf("policy: unsupported mode %q (expected \"enforce\" or \"audit\")", pf.Mode)
	}
	if len(pf.Rules) == 0 {
		return fmt.Errorf("policy: no rules defined")
	}
	for i, r := range pf.Rules {
		if r.Name == "" {
			return fmt.Errorf("policy: rule[%d]: name is required", i)
		}
		if r.Action != "allow" && r.Action != "deny" {
			return fmt.Errorf("policy: rule[%d] %q: unsupported action %q (expected \"allow\" or \"deny\")", i, r.Name, r.Action)
		}
		if r.Mode != "" && r.Mode != "enforce" && r.Mode != "audit" {
			return fmt.Errorf("policy: rule[%d] %q: unsupported mode %q (expected \"enforce\", \"audit\", or empty)", i, r.Name, r.Mode)
		}
		if len(r.Match.Methods) == 0 {
			return fmt.Errorf("policy: rule[%d] %q: at least one method pattern is required", i, r.Name)
		}
		if len(r.Match.Arguments) > 0 {
			// arguments は tools/call 専用
			hasToolsCall := false
			for _, m := range r.Match.Methods {
				if m == "tools/call" {
					hasToolsCall = true
					break
				}
			}
			if !hasToolsCall {
				return fmt.Errorf("policy: rule[%d] %q: arguments requires methods to include \"tools/call\"", i, r.Name)
			}
			for argName, patterns := range r.Match.Arguments {
				if len(patterns) == 0 {
					return fmt.Errorf("policy: rule[%d] %q: arguments[%q] must have at least one pattern", i, r.Name, argName)
				}
			}
		}
		if len(r.Match.ArgumentPatterns) > 0 {
			// argument_patterns は tools/call 専用
			hasToolsCall := false
			for _, m := range r.Match.Methods {
				if m == "tools/call" {
					hasToolsCall = true
					break
				}
			}
			if !hasToolsCall {
				return fmt.Errorf("policy: rule[%d] %q: argument_patterns requires methods to include \"tools/call\"", i, r.Name)
			}
			for argName, patterns := range r.Match.ArgumentPatterns {
				if len(patterns) == 0 {
					return fmt.Errorf("policy: rule[%d] %q: argument_patterns[%q] must have at least one pattern", i, r.Name, argName)
				}
				for _, p := range patterns {
					if _, err := regexp.Compile(p); err != nil {
						return fmt.Errorf("policy: rule[%d] %q: argument_patterns[%q]: invalid regex %q: %w", i, r.Name, argName, p, err)
					}
				}
			}
		}
	}
	// response_patterns のバリデーション
	for _, p := range pf.ResponsePatterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("policy: response_patterns: invalid regex %q: %w", p, err)
		}
	}
	return nil
}
