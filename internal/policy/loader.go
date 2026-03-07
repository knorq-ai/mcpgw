package policy

import (
	"fmt"
	"os"

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
		if len(r.Match.Methods) == 0 {
			return fmt.Errorf("policy: rule[%d] %q: at least one method pattern is required", i, r.Name)
		}
	}
	return nil
}
