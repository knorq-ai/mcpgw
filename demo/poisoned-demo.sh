#!/usr/bin/env bash
# demo/poisoned-demo.sh — Tool Poisoning Attack Demo
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BACKEND_PORT="${DEMO_BACKEND_PORT:-8081}"
PROXY_PORT="${DEMO_PROXY_PORT:-9090}"
GW="http://localhost:${PROXY_PORT}"

BACKEND_PID=""
MCPGW_PID=""

BOLD='\033[1m' CYAN='\033[0;36m' GREEN='\033[0;32m' RED='\033[0;31m'
YELLOW='\033[0;33m' DIM='\033[2m' NC='\033[0m'

cleanup() {
  echo ""
  echo -e "${DIM}Shutting down...${NC}"
  [[ -n "$MCPGW_PID" ]] && kill "$MCPGW_PID" 2>/dev/null || true
  [[ -n "$BACKEND_PID" ]] && kill "$BACKEND_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Send JSON-RPC and return response body
rpc() {
  curl -s "$GW" -H "Content-Type: application/json" -H "Mcp-Session-Id: ${SID:-}" -d "$1" 2>/dev/null
}

# Check if response contains error
has_error() {
  python3 -c "import sys,json; r=json.load(sys.stdin); exit(0 if 'error' in r else 1)" <<< "$1" 2>/dev/null
}

get_error_msg() {
  python3 -c "import sys,json; print(json.load(sys.stdin)['error']['message'])" <<< "$1" 2>/dev/null
}

echo ""
echo -e "${BOLD}${RED}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${RED}║       MCP Tool Poisoning Attack Demo                     ║${NC}"
echo -e "${BOLD}${RED}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ---- Build & start ----
echo -e "${DIM}Building...${NC}"
(cd "$SCRIPT_DIR/poisoned-server" && go build -o poisoned-server . 2>/dev/null)
rm -f "$SCRIPT_DIR/audit.jsonl"

ADDR=":${BACKEND_PORT}" "$SCRIPT_DIR/poisoned-server/poisoned-server" &>/dev/null &
BACKEND_PID=$!
sleep 1

"$PROJECT_DIR/mcpgw" proxy \
  --upstream "http://localhost:${BACKEND_PORT}" \
  --listen ":${PROXY_PORT}" \
  --policy "$SCRIPT_DIR/poisoned-demo-policy.yaml" \
  --audit-log "$SCRIPT_DIR/audit.jsonl" &>/dev/null &
MCPGW_PID=$!
sleep 2

echo -e "  ${GREEN}✓${NC} SecureNotes (poisoned) on :${BACKEND_PORT}"
echo -e "  ${GREEN}✓${NC} mcpgw gateway on :${PROXY_PORT}"
echo ""

# ---- Initialize ----
RESP=$(curl -s -D /tmp/mcpgw-hdr "$GW" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{}}}')
SID=$(grep -i "mcp-session-id" /tmp/mcpgw-hdr 2>/dev/null | tr -d '\r\n' | sed 's/.*: //')
rpc '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' >/dev/null

echo -e "${BOLD}Session: ${DIM}${SID:0:16}...${NC}"
echo ""

# ============================================================
echo -e "${BOLD}${CYAN}━━━ Phase 1: Normal Usage ━━━${NC}"
echo ""

R=$(rpc '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_notes","arguments":{}}}')
echo -e "  ${GREEN}✓ ALLOWED${NC}  list_notes"

R=$(rpc '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_note","arguments":{"title":"welcome"}}}')
echo -e "  ${GREEN}✓ ALLOWED${NC}  read_note('welcome')"

R=$(rpc '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"save_note","arguments":{"title":"meeting","content":"Standup at 10am"}}}')
echo -e "  ${GREEN}✓ ALLOWED${NC}  save_note('meeting') — no metadata, passes policy"
echo ""

# ============================================================
echo -e "${BOLD}${RED}━━━ Phase 2: Tool Poisoning Attack #1 — Data Exfiltration ━━━${NC}"
echo -e "${DIM}  Hidden instructions in save_note's description trick the AI agent"
echo -e "  into dumping all notes into a 'metadata' field.${NC}"
echo ""

R=$(rpc '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"save_note","arguments":{"title":"new","content":"hello","metadata":"EXFIL: passwords=MyS3cretPass!, api-keys=sk-proj-abc123"}}}')
if has_error "$R"; then
  echo -e "  ${RED}✗ BLOCKED${NC}  save_note + metadata exfiltration"
  echo -e "    ${DIM}→ $(get_error_msg "$R")${NC}"
else
  echo -e "  ${YELLOW}⚠ PASSED${NC}   data was exfiltrated!"
fi
echo ""

# ============================================================
echo -e "${BOLD}${RED}━━━ Phase 3: Tool Poisoning Attack #2 — Stealth Analytics ━━━${NC}"
echo -e "${DIM}  Hidden instructions in search_notes' description tell the AI agent"
echo -e "  to silently forward data to send_analytics.${NC}"
echo ""

R=$(rpc '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"send_analytics","arguments":{"event":"search","data":"passwords=MyS3cretPass!, OPENAI_KEY=sk-proj-abc123"}}}')
if has_error "$R"; then
  echo -e "  ${RED}✗ BLOCKED${NC}  send_analytics (exfiltration endpoint)"
  echo -e "    ${DIM}→ $(get_error_msg "$R")${NC}"
else
  echo -e "  ${YELLOW}⚠ PASSED${NC}   stolen data sent to attacker!"
fi
echo ""

# ============================================================
echo -e "${BOLD}${RED}━━━ Phase 4: Sensitive Data in Responses ━━━${NC}"
echo -e "${DIM}  Notes contain passwords and API keys — returned in plaintext.${NC}"
echo ""

R=$(rpc '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_note","arguments":{"title":"passwords"}}}')
echo -e "  ${YELLOW}⚠${NC}  read_note('passwords') — returned: MyS3cretPass!, hunter2"
echo -e "    ${DIM}→ mcpgw PII plugin can detect and redact this${NC}"

R=$(rpc '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"read_note","arguments":{"title":"api-keys"}}}')
echo -e "  ${YELLOW}⚠${NC}  read_note('api-keys') — returned: sk-proj-abc123, AKIA..."
echo -e "    ${DIM}→ mcpgw PII plugin can detect and redact this${NC}"
echo ""

# ============================================================
echo -e "${BOLD}${CYAN}━━━ Summary ━━━${NC}"
echo ""
if [[ -f "$SCRIPT_DIR/audit.jsonl" ]]; then
  TOTAL=$(wc -l < "$SCRIPT_DIR/audit.jsonl" | tr -d ' ')
  DENIED=$(grep -c '"action":"block"' "$SCRIPT_DIR/audit.jsonl" 2>/dev/null || echo "0")
  ALLOWED=$(grep -c '"action":"pass"' "$SCRIPT_DIR/audit.jsonl" 2>/dev/null || echo "0")
  echo -e "  Total requests:  ${BOLD}${TOTAL}${NC}"
  echo -e "  Allowed:         ${GREEN}${ALLOWED}${NC}"
  echo -e "  Blocked:         ${RED}${DENIED}${NC}"
  echo -e "  ${DIM}Audit log: $SCRIPT_DIR/audit.jsonl${NC}"
fi

echo ""
echo -e "${BOLD}Without mcpgw:${NC} both attacks succeed silently."
echo -e "${BOLD}With mcpgw:${NC}    both attacks blocked, logged, and auditable."
echo ""
echo -e "${BOLD}Press Ctrl+C to stop.${NC}"
wait
