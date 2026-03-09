#!/usr/bin/env bash
# demo/run.sh — デモ環境のプロセスライフサイクル管理。
# demo-server と mcpgw を起動し、simulate.sh を実行する。
# Ctrl+C で全プロセスを停止する。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ポート設定（環境変数で上書き可能）
DEMO_BACKEND_PORT="${DEMO_BACKEND_PORT:-8080}"
DEMO_PROXY_PORT="${DEMO_PROXY_PORT:-9090}"
DEMO_MGMT_PORT="${DEMO_MGMT_PORT:-9091}"
export DEMO_BACKEND_PORT DEMO_PROXY_PORT DEMO_MGMT_PORT

DEMO_SERVER_PID=""
MCPGW_PID=""

BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

cleanup() {
  echo ""
  echo -e "${BOLD}Shutting down...${NC}"
  [[ -n "$MCPGW_PID" ]] && kill "$MCPGW_PID" 2>/dev/null && wait "$MCPGW_PID" 2>/dev/null || true
  [[ -n "$DEMO_SERVER_PID" ]] && kill "$DEMO_SERVER_PID" 2>/dev/null && wait "$DEMO_SERVER_PID" 2>/dev/null || true
  echo -e "${GREEN}All processes stopped.${NC}"
}

trap cleanup EXIT INT TERM

# ポートが利用可能になるまで待機
wait_for_port() {
  local port="$1"
  local name="$2"
  local max_wait=10
  local i=0
  while ! curl -sf "http://localhost:${port}" -o /dev/null 2>/dev/null && \
        ! curl -sf "http://localhost:${port}/healthz" -o /dev/null 2>/dev/null; do
    i=$((i + 1))
    if (( i >= max_wait )); then
      echo -e "${RED}Timeout waiting for ${name} on port ${port}${NC}" >&2
      exit 1
    fi
    sleep 1
  done
  echo -e "  ${GREEN}✓${NC} ${name} ready on :${port}"
}

echo ""
echo -e "${BOLD}${CYAN}Starting mcpgw demo environment...${NC}"
echo ""

# ---- 既存の audit ログをクリア ----
rm -f "$PROJECT_DIR/demo/audit.jsonl"

# ---- demo-server 起動 ----
echo -e "${BOLD}Starting demo-server on :${DEMO_BACKEND_PORT}...${NC}"
DEMO_SERVER_ADDR=":${DEMO_BACKEND_PORT}" "$PROJECT_DIR/demo/server/demo-server" &
DEMO_SERVER_PID=$!

# POST にのみ応答するので、空 POST で待機
wait_for_port_post() {
  local port="$1"
  local name="$2"
  local max_wait=10
  local i=0
  while true; do
    local status
    status=$(curl -s -o /dev/null -w '%{http_code}' \
      -X POST "http://localhost:${port}" \
      -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":0,"method":"ping"}' 2>/dev/null) || true
    # 400 以外のレスポンスが返ればサーバーは起動済み
    if [[ "$status" != "000" ]]; then
      break
    fi
    i=$((i + 1))
    if (( i >= max_wait )); then
      echo -e "${RED}Timeout waiting for ${name} on port ${port}${NC}" >&2
      exit 1
    fi
    sleep 1
  done
  echo -e "  ${GREEN}✓${NC} ${name} ready on :${port}"
}

wait_for_port_post "$DEMO_BACKEND_PORT" "demo-server"

# ---- mcpgw 起動 ----
echo -e "${BOLD}Starting mcpgw on :${DEMO_PROXY_PORT} (dashboard :${DEMO_MGMT_PORT})...${NC}"
"$PROJECT_DIR/mcpgw" proxy --config "$PROJECT_DIR/demo/config.yaml" &
MCPGW_PID=$!

wait_for_port "$DEMO_MGMT_PORT" "mcpgw (management)"

echo ""
echo -e "${GREEN}All services ready.${NC}"
echo ""

# ---- シミュレーション実行 ----
MCPGW_URL="http://localhost:${DEMO_PROXY_PORT}" bash "$SCRIPT_DIR/simulate.sh"

# ---- ダッシュボード案内 & 待機 ----
echo ""
echo -e "${BOLD}Dashboard: ${CYAN}http://localhost:${DEMO_MGMT_PORT}${NC}"
echo -e "${BOLD}Press Ctrl+C to stop all services.${NC}"
echo ""

# 無限待機（Ctrl+C で trap → cleanup）
wait
