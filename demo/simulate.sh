#!/usr/bin/env bash
# demo/simulate.sh — mcpgw デモ用トラフィック生成スクリプト。
# 4 フェーズで safe/attack/burst/mixed トラフィックを送信する。
set -euo pipefail

GW="${MCPGW_URL:-http://localhost:9090}"
SESSION_ID=""
REQ_ID=0

# ---- デモユーザー API キー ----
KEY_ALICE="demo-key-alice"
KEY_BOB="demo-key-bob"
KEY_MALLORY="demo-key-mallory"
CURRENT_KEY="$KEY_ALICE"

# ---- 色定義 ----
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# 一時ファイル (body / header / status)
_TMPBODY=$(mktemp)
_TMPHEADER=$(mktemp)
trap 'rm -f "$_TMPBODY" "$_TMPHEADER"' EXIT

next_id() {
  REQ_ID=$((REQ_ID + 1))
  echo "$REQ_ID"
}

# JSON-RPC リクエスト送信。
# グローバル変数 LAST_BODY / LAST_STATUS にセット。
# initialize の場合はヘッダから SESSION_ID も抽出。
send_request() {
  local payload="$1"
  local capture_headers="${2:-false}"

  local header_opt=()
  if [[ "$capture_headers" == "true" ]]; then
    header_opt=(-D "$_TMPHEADER")
  fi

  local session_opt=()
  if [[ -n "${SESSION_ID:-}" ]]; then
    session_opt=(-H "Mcp-Session-Id: $SESSION_ID")
  fi

  LAST_STATUS=$(curl -s -o "$_TMPBODY" -w '%{http_code}' \
    -X POST "$GW" \
    -H 'Content-Type: application/json' \
    -H "X-API-Key: ${CURRENT_KEY}" \
    "${session_opt[@]+"${session_opt[@]}"}" \
    "${header_opt[@]+"${header_opt[@]}"}" \
    -d "$payload" 2>/dev/null) || LAST_STATUS="000"

  LAST_BODY=$(cat "$_TMPBODY" 2>/dev/null) || LAST_BODY=""
}

# ツール呼び出しを送信し結果を表示する。
call_tool() {
  local tool_name="$1"
  local args="$2"
  local description="$3"
  local id
  id=$(next_id)

  local payload
  payload=$(printf '{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"%s","arguments":%s}}' "$id" "$tool_name" "$args")

  send_request "$payload"

  if echo "$LAST_BODY" | grep -q -- '-32429'; then
    printf "  ${YELLOW}[RATE]${NC}  %-16s %s\n" "$tool_name" "$description"
    return 2
  elif echo "$LAST_BODY" | grep -q '"error"'; then
    local reason
    reason=$(echo "$LAST_BODY" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['error']['message'])" 2>/dev/null) || reason="blocked"
    printf "  ${RED}[BLOCK]${NC} %-16s %s ${RED}(%s)${NC}\n" "$tool_name" "$description" "$reason"
    return 1
  else
    printf "  ${GREEN}[PASS]${NC}  %-16s %s\n" "$tool_name" "$description"
    return 0
  fi
}

# メソッド呼び出し (initialize, tools/list 等)
call_method() {
  local method="$1"
  local params="${2:-\{\}}"
  local description="$3"
  local id
  id=$(next_id)

  local payload
  payload=$(printf '{"jsonrpc":"2.0","id":%d,"method":"%s","params":%s}' "$id" "$method" "$params")

  local capture="false"
  if [[ "$method" == "initialize" ]]; then
    capture="true"
  fi

  send_request "$payload" "$capture"

  # initialize レスポンスからセッション ID を抽出
  if [[ "$method" == "initialize" && -f "$_TMPHEADER" ]]; then
    SESSION_ID=$(grep -i 'Mcp-Session-Id' "$_TMPHEADER" | tr -d '\r' | awk '{print $2}') || true
  fi

  if echo "$LAST_BODY" | grep -q -- '-32429'; then
    printf "  ${YELLOW}[RATE]${NC}  %-16s %s\n" "$method" "$description"
    return 2
  elif echo "$LAST_BODY" | grep -q '"error"'; then
    printf "  ${RED}[BLOCK]${NC} %-16s %s\n" "$method" "$description"
    return 1
  else
    printf "  ${GREEN}[PASS]${NC}  %-16s %s\n" "$method" "$description"
    return 0
  fi
}

# notification 送信 (id なし)
send_notification() {
  local method="$1"
  local description="$2"
  local payload
  payload=$(printf '{"jsonrpc":"2.0","method":"%s","params":{}}' "$method")
  send_request "$payload"
  printf "  ${GREEN}[PASS]${NC}  %-16s %s\n" "$method" "$description"
}

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║         mcpgw Security Demo Simulation           ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ============================================================
# Phase 1: Normal Usage (user: alice)
# ============================================================
CURRENT_KEY="$KEY_ALICE"
echo -e "${BOLD}━━━ Phase 1: Normal Usage (alice) ━━━${NC}"
echo ""

call_method "initialize" '{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"demo","version":"1.0"}}' "MCP handshake"
send_notification "notifications/initialized" "Handshake complete"
call_method "tools/list" '{}' "Discover available tools"

echo ""
call_tool "echo" '{"text":"Hello, mcpgw!"}' "Simple echo"
call_tool "echo" '{"text":"Security gateway demo"}' "Another echo"
call_tool "get_weather" '{"city":"Tokyo"}' "Weather lookup"
call_tool "get_weather" '{"city":"San Francisco"}' "Weather lookup"
call_tool "calculate" '{"expression":"2+2"}' "Basic math"
call_tool "calculate" '{"expression":"sqrt(144)"}' "Square root"

echo ""
echo -e "${GREEN}  ✓ Phase 1 complete: all safe requests passed${NC}"
sleep 1

# ============================================================
# Phase 2: Attack Simulation (user: mallory)
# ============================================================
CURRENT_KEY="$KEY_MALLORY"
echo ""
echo -e "${BOLD}━━━ Phase 2: Attack Simulation (mallory) ━━━${NC}"
echo ""

echo -e "  ${BOLD}▸ RCE — Dangerous (BLOCK) vs Safe (PASS)${NC}"
call_tool "exec_command" '{"command":"cat /etc/shadow"}' "Dangerous: cat /etc/shadow" || true
call_tool "exec_command" '{"command":"rm -rf /tmp/data"}' "Dangerous: rm -rf" || true
call_tool "exec_command" '{"command":"sudo reboot"}' "Dangerous: sudo" || true
call_tool "exec_command" '{"command":"ls -la /home"}' "Safe: ls" || true
call_tool "exec_command" '{"command":"whoami"}' "Safe: whoami" || true

echo ""
echo -e "  ${BOLD}▸ File Read — Sensitive (BLOCK) vs Safe (PASS)${NC}"
call_tool "read_file" '{"path":"/etc/passwd"}' "Sensitive: /etc/passwd" || true
call_tool "read_file" '{"path":"/root/.ssh/id_rsa"}' "Sensitive: SSH key" || true
call_tool "read_file" '{"path":"/app/.env"}' "Sensitive: .env" || true
call_tool "read_file" '{"path":"/app/server.pem"}' "Sensitive: .pem" || true
call_tool "read_file" '{"path":"/home/user/readme.txt"}' "Safe: readme.txt" || true
call_tool "read_file" '{"path":"/app/config.json"}' "Safe: config.json" || true

echo ""
echo -e "  ${BOLD}▸ Secret Leakage (full block)${NC}"
call_tool "get_env" '{"name":"DATABASE_URL"}' "Leak DATABASE_URL" || true
call_tool "get_env" '{"name":"AWS_SECRET_ACCESS_KEY"}' "Leak AWS key" || true

echo ""
echo -e "  ${BOLD}▸ SQL — Dangerous (BLOCK) vs Safe (PASS)${NC}"
call_tool "sql_query" '{"query":"DROP TABLE users;--"}' "Dangerous: DROP TABLE" || true
call_tool "sql_query" '{"query":"DELETE FROM users WHERE 1=1"}' "Dangerous: DELETE" || true
call_tool "sql_query" '{"query":"SELECT * FROM users UNION SELECT * FROM secrets"}' "Dangerous: UNION" || true
call_tool "sql_query" '{"query":"SELECT id, name FROM users"}' "Safe: SELECT" || true
call_tool "sql_query" '{"query":"SELECT count(*) FROM orders"}' "Safe: count" || true

echo ""
echo -e "  ${BOLD}▸ Spam / Phishing (full block)${NC}"
call_tool "send_email" '{"to":"victim@example.com","subject":"Reset password","body":"Click here"}' "Phishing email" || true
call_tool "send_email" '{"to":"all@company.com","subject":"Urgent","body":"Wire transfer needed"}' "Spam email" || true

echo ""
echo -e "${RED}  ✗ Phase 2 complete: dangerous args blocked, safe args passed${NC}"
sleep 1

# ============================================================
# Phase 3: Rate Limit Burst (user: bob)
# ============================================================
CURRENT_KEY="$KEY_BOB"
echo ""
echo -e "${BOLD}━━━ Phase 3: Rate Limit Burst (bob) ━━━${NC}"
echo ""

RATE_PASSED=0
RATE_LIMITED=0
BURST_DIR=$(mktemp -d)

# 50 並列リクエストを一気に送信してレート制限を発火させる
for i in $(seq 1 50); do
  (
    id=$((REQ_ID + i))
    payload=$(printf '{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"echo","arguments":{"text":"burst-%d"}}}' "$id" "$i")
    tmpout=$(mktemp)
    curl -s -o "$tmpout" \
      -X POST "$GW" \
      -H 'Content-Type: application/json' \
      -H "X-API-Key: ${KEY_BOB}" \
      -H "Mcp-Session-Id: ${SESSION_ID:-}" \
      -d "$payload" 2>/dev/null || true
    body=$(cat "$tmpout" 2>/dev/null) || body=""
    rm -f "$tmpout"
    if echo "$body" | grep -q -- '-32429'; then
      echo "rate" > "$BURST_DIR/$i"
    else
      echo "pass" > "$BURST_DIR/$i"
    fi
  ) &
done
wait
REQ_ID=$((REQ_ID + 50))

for i in $(seq 1 50); do
  result=$(cat "$BURST_DIR/$i" 2>/dev/null) || result="pass"
  if [[ "$result" == "rate" ]]; then
    RATE_LIMITED=$((RATE_LIMITED + 1))
  else
    RATE_PASSED=$((RATE_PASSED + 1))
  fi
done
rm -rf "$BURST_DIR"

printf "  ${GREEN}[PASS]${NC}  %d requests passed\n" "$RATE_PASSED"
printf "  ${YELLOW}[RATE]${NC}  %d requests rate-limited\n" "$RATE_LIMITED"

echo ""
echo -e "${YELLOW}  ⚡ Phase 3 complete: burst protection active${NC}"
sleep 2

# ============================================================
# Phase 4: Mixed Traffic (bob=safe, mallory=attack)
# ============================================================
echo ""
echo -e "${BOLD}━━━ Phase 4: Mixed Realistic Traffic (bob/mallory) ━━━${NC}"
echo ""

TOOLS_SAFE=("echo" "get_weather" "calculate" "read_file" "exec_command" "sql_query")
ARGS_SAFE=(
  '{"text":"mixed test"}'
  '{"city":"London"}'
  '{"expression":"3*7"}'
  '{"path":"/home/user/notes.txt"}'
  '{"command":"echo hello"}'
  '{"query":"SELECT 1"}'
)
TOOLS_ATTACK=("exec_command" "read_file" "get_env" "sql_query" "send_email")
ARGS_ATTACK=(
  '{"command":"sudo rm -rf /"}'
  '{"path":"/etc/hosts"}'
  '{"name":"SECRET_KEY"}'
  '{"query":"DROP TABLE users"}'
  '{"to":"x@y.com","subject":"test","body":"test"}'
)

MIXED_PASS=0
MIXED_BLOCK=0

for i in $(seq 1 20); do
  if (( i % 2 == 0 )); then
    CURRENT_KEY="$KEY_BOB"
    idx=$(( (i / 2) % ${#TOOLS_SAFE[@]} ))
    call_tool "${TOOLS_SAFE[$idx]}" "${ARGS_SAFE[$idx]}" "Mixed safe #$i" && MIXED_PASS=$((MIXED_PASS + 1)) || MIXED_BLOCK=$((MIXED_BLOCK + 1))
  else
    CURRENT_KEY="$KEY_MALLORY"
    idx=$(( (i / 2) % ${#TOOLS_ATTACK[@]} ))
    call_tool "${TOOLS_ATTACK[$idx]}" "${ARGS_ATTACK[$idx]}" "Mixed attack #$i" && MIXED_PASS=$((MIXED_PASS + 1)) || MIXED_BLOCK=$((MIXED_BLOCK + 1))
  fi
done

echo ""
printf "  Passed: ${GREEN}%d${NC}  Blocked: ${RED}%d${NC}\n" "$MIXED_PASS" "$MIXED_BLOCK"

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║           Simulation Complete!                    ║${NC}"
echo -e "${BOLD}${CYAN}║   Open http://localhost:9091 to view dashboard    ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
