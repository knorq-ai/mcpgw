package dashboard

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/knorq-ai/mcpgw/internal/policy"
)

// maxPolicyBodySize はポリシー YAML ボディの最大サイズ。
const maxPolicyBodySize = 1 * 1024 * 1024 // 1MB

type policyUpdateResponse struct {
	OK      bool           `json:"ok"`
	Policy  *policyResponse `json:"policy,omitempty"`
	Error   string         `json:"error,omitempty"`
}

// handlePolicyUpdate は PUT /api/policy のハンドラ。
// YAML ボディを受け取り、バリデーション → バックアップ → アトミック書き込み → ホットリロードを行う。
func handlePolicyUpdate(policyPath string, provider PolicyProvider, swappers []EngineSwapper) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if policyPath == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(policyUpdateResponse{
				Error: "policy path is not configured",
			})
			return
		}

		// ボディ読み込み（サイズ制限付き）
		body, err := io.ReadAll(io.LimitReader(r.Body, maxPolicyBodySize+1))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(policyUpdateResponse{
				Error: fmt.Sprintf("failed to read request body: %v", err),
			})
			return
		}
		if int64(len(body)) > maxPolicyBodySize {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			json.NewEncoder(w).Encode(policyUpdateResponse{
				Error: "request body too large",
			})
			return
		}
		if len(body) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(policyUpdateResponse{
				Error: "empty request body",
			})
			return
		}

		// ポリシーのパースとバリデーション
		pf, err := policy.Parse(body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(policyUpdateResponse{
				Error: fmt.Sprintf("policy validation failed: %v", err),
			})
			return
		}

		// 旧ポリシーのバックアップ（存在する場合）
		bakPath := policyPath + ".bak"
		if _, statErr := os.Stat(policyPath); statErr == nil {
			if cpErr := copyFile(policyPath, bakPath); cpErr != nil {
				slog.Warn("failed to create policy backup", "error", cpErr)
				// バックアップ失敗でも続行する
			}
		}

		// 一時ファイル書き込み → アトミックリネーム
		dir := filepath.Dir(policyPath)
		tmp, err := os.CreateTemp(dir, ".policy-*.yaml.tmp")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(policyUpdateResponse{
				Error: fmt.Sprintf("failed to create temp file: %v", err),
			})
			return
		}
		tmpPath := tmp.Name()

		if _, err := tmp.Write(body); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(policyUpdateResponse{
				Error: fmt.Sprintf("failed to write temp file: %v", err),
			})
			return
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmpPath)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(policyUpdateResponse{
				Error: fmt.Sprintf("failed to close temp file: %v", err),
			})
			return
		}

		if err := os.Rename(tmpPath, policyPath); err != nil {
			os.Remove(tmpPath)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(policyUpdateResponse{
				Error: fmt.Sprintf("failed to rename temp file: %v", err),
			})
			return
		}

		// エンジンの入れ替え（ホットリロード）
		engine := policy.NewEngine(pf)
		for _, s := range swappers {
			s.SwapEngine(engine)
		}

		slog.Info("policy updated via dashboard", "rules", len(pf.Rules), "mode", pf.Mode)

		// レスポンス組み立て
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

		json.NewEncoder(w).Encode(policyUpdateResponse{
			OK: true,
			Policy: &policyResponse{
				Version:          pf.Version,
				Mode:             pf.Mode,
				Rules:            rules,
				ResponsePatterns: pf.ResponsePatterns,
				AllowedTools:     pf.AllowedTools,
			},
		})
	}
}

// copyFile は src を dst にコピーする。
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
