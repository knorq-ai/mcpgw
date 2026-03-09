package dashboard

import (
	"encoding/json"
	"net/http"
)

type policyResponse struct {
	Version          string       `json:"version"`
	Mode             string       `json:"mode"`
	Rules            []policyRule `json:"rules"`
	ResponsePatterns []string     `json:"response_patterns,omitempty"`
	AllowedTools     []string     `json:"allowed_tools,omitempty"`
}

type policyRule struct {
	Name             string              `json:"name"`
	Methods          []string            `json:"methods"`
	Tools            []string            `json:"tools,omitempty"`
	Subjects         []string            `json:"subjects,omitempty"`
	Arguments        map[string][]string `json:"arguments,omitempty"`
	ArgumentPatterns map[string][]string `json:"argument_patterns,omitempty"`
	Action           string              `json:"action"`
	Mode             string              `json:"mode,omitempty"`
}

func handlePolicy(provider PolicyProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if provider == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(policyResponse{Rules: []policyRule{}})
			return
		}

		pf := provider.PolicyFile()
		if pf == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(policyResponse{Rules: []policyRule{}})
			return
		}

		rules := make([]policyRule, 0, len(pf.Rules))
		for _, r := range pf.Rules {
			rules = append(rules, policyRule{
				Name:             r.Name,
				Methods:          r.Match.Methods,
				Tools:            r.Match.Tools,
				Subjects:         r.Match.Subjects,
				Arguments:        r.Match.Arguments,
				ArgumentPatterns: r.Match.ArgumentPatterns,
				Action:           r.Action,
				Mode:             r.Mode,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(policyResponse{
			Version:          pf.Version,
			Mode:             pf.Mode,
			Rules:            rules,
			ResponsePatterns: pf.ResponsePatterns,
			AllowedTools:     pf.AllowedTools,
		})
	}
}
