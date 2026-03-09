package dashboard

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/knorq-ai/mcpgw/web"
)

// spaHandler は SPA（Single Page Application）用のファイルサーバーを返す。
// 静的ファイルが存在すればそれを返し、存在しなければ index.html にフォールバックする。
func spaHandler() http.Handler {
	distFS, err := fs.Sub(web.DistFS, "dist")
	if err != nil {
		// embed が不正な場合はビルド時エラー
		panic("dashboard: failed to sub dist from embed: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(distFS))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /api/, /metrics, /healthz, /readyz はスキップ（上位 mux で処理済み）
		path := r.URL.Path
		if strings.HasPrefix(path, "/api/") ||
			path == "/metrics" ||
			path == "/healthz" ||
			path == "/readyz" {
			http.NotFound(w, r)
			return
		}

		// 静的ファイルが存在するか確認
		cleanPath := strings.TrimPrefix(path, "/")
		if cleanPath == "" {
			cleanPath = "index.html"
		}
		if _, err := fs.Stat(distFS, cleanPath); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}

		// SPA フォールバック: index.html を返す
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}
