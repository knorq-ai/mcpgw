package dashboard

import (
	"encoding/json"
	"net/http"

	"github.com/knorq-ai/mcpgw/internal/policy"
)

// testScenario は POST /api/policy/test のリクエスト内の個々のシナリオ。
type testScenario struct {
	Name    string   `json:"name"`
	Method  string   `json:"method"`
	Params  string   `json:"params"` // JSON 文字列
	Subject string   `json:"subject,omitempty"`
	Roles   []string `json:"roles,omitempty"`
	Expect  string   `json:"expect"` // "allow" or "deny"
}

// testRequest は POST /api/policy/test のリクエストボディ。
type testRequest struct {
	Scenarios []testScenario `json:"scenarios"`
}

// testResult は個々のシナリオの評価結果。
type testResult struct {
	Name     string `json:"name"`
	Method   string `json:"method"`
	Expect   string `json:"expect"`
	Actual   string `json:"actual"`
	RuleName string `json:"rule_name"`
	Mode     string `json:"mode"`
	Pass     bool   `json:"pass"`
}

// testResponse は POST /api/policy/test のレスポンス。
type testResponse struct {
	Results []testResult `json:"results"`
	Passed  int          `json:"passed"`
	Failed  int          `json:"failed"`
	Total   int          `json:"total"`
}

// handlePolicyTest は POST /api/policy/test のハンドラ。
// 現在のポリシーに対してテストシナリオを評価し、結果を返す（dry-run）。
func handlePolicyTest(provider PolicyProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if provider == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "policy provider is not configured",
			})
			return
		}

		pf := provider.PolicyFile()
		if pf == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "no policy loaded",
			})
			return
		}

		var req testRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "invalid request body: " + err.Error(),
			})
			return
		}

		if len(req.Scenarios) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "no scenarios provided",
			})
			return
		}

		// バリデーション
		for i, sc := range req.Scenarios {
			if sc.Name == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": scenarioValidationError(i, "name is required"),
				})
				return
			}
			if sc.Method == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": scenarioValidationError(i, "method is required"),
				})
				return
			}
			if sc.Expect != "allow" && sc.Expect != "deny" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": scenarioValidationError(i, "expect must be \"allow\" or \"deny\""),
				})
				return
			}
			if sc.Params != "" && !json.Valid([]byte(sc.Params)) {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": scenarioValidationError(i, "params is not valid JSON"),
				})
				return
			}
		}

		// 現在のポリシーでエンジンを構築して評価
		engine := policy.NewEngine(pf)
		results := make([]testResult, 0, len(req.Scenarios))
		passed, failed := 0, 0

		for _, sc := range req.Scenarios {
			var params json.RawMessage
			if sc.Params != "" {
				params = json.RawMessage(sc.Params)
			}

			decision := engine.EvaluateWithInput(policy.EvaluateInput{
				Method:  sc.Method,
				Params:  params,
				Subject: sc.Subject,
				Roles:   sc.Roles,
			})

			actual := "deny"
			if decision.Allow {
				actual = "allow"
			}

			pass := actual == sc.Expect
			if pass {
				passed++
			} else {
				failed++
			}

			results = append(results, testResult{
				Name:     sc.Name,
				Method:   sc.Method,
				Expect:   sc.Expect,
				Actual:   actual,
				RuleName: decision.RuleName,
				Mode:     decision.Mode,
				Pass:     pass,
			})
		}

		json.NewEncoder(w).Encode(testResponse{
			Results: results,
			Passed:  passed,
			Failed:  failed,
			Total:   len(req.Scenarios),
		})
	}
}

// scenarioValidationError はシナリオバリデーションのエラーメッセージを組み立てる。
func scenarioValidationError(index int, msg string) string {
	return "scenario[" + json.Number(itoa(index)).String() + "]: " + msg
}

// itoa は int を文字列に変換する（strconv 不要な簡易版）。
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf) - 1
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	for i > 0 {
		buf[pos] = byte('0' + i%10)
		pos--
		i /= 10
	}
	if neg {
		buf[pos] = '-'
		pos--
	}
	return string(buf[pos+1:])
}
