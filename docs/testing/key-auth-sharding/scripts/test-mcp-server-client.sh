#!/bin/bash
# Usage: ./test-mcp-server-client.sh <transport> <url> [options]
#   transport: sse | streamable
#   url: MCP server endpoint URL
#
# Options:
#   --debug              Print full curl commands for tools/call so you can copy & tweak
#   --tool <name>        Specify which tool to call (default: first tool from tools/list)
#   --args '<json>'      Specify arguments JSON, overrides auto-generated values
#                        Use single quotes around JSON to avoid shell escaping issues
#   --header '<header>'  Add custom header to all requests (can be repeated)
#                        e.g. --header 'Authorization: Bearer mykey'
#
# Examples:
#   ./test-mcp-server-client.sh sse http://8.137.146.50/mcp-servers/eliot-test4/sse
#   ./test-mcp-server-client.sh streamable http://8.137.146.50/mcp-servers/eliot-test4 --debug
#   ./test-mcp-server-client.sh streamable http://example.com/mcp --tool echo --args '{"message":"hi"}'
#   ./test-mcp-server-client.sh streamable http://example.com/mcp --tool findBooks --args '{"query":"AI"}' --debug
#   ./test-mcp-server-client.sh sse http://gw/mcp-servers/test/sse --header 'Authorization: Bearer mykey'

set -e

TRANSPORT="$1"
URL="$2"
DEBUG=false
USER_TOOL=""
USER_ARGS=""
CUSTOM_HEADERS=()

# Parse optional flags
shift 2 2>/dev/null || true
while [ $# -gt 0 ]; do
  case "$1" in
    --debug) DEBUG=true ;;
    --tool)  shift; USER_TOOL="$1" ;;
    --args)  shift; USER_ARGS="$1" ;;
    --header) shift; CUSTOM_HEADERS+=("$1") ;;
  esac
  shift
done

if [ -z "$TRANSPORT" ] || [ -z "$URL" ]; then
  echo "Usage: $0 <sse|streamable> <url> [--debug] [--tool <name>] [--args '<json>']"
  exit 1
fi

# Validate --args is valid JSON if provided
if [ -n "$USER_ARGS" ]; then
  if ! echo "$USER_ARGS" | jq . >/dev/null 2>&1; then
    echo "Error: --args value is not valid JSON: $USER_ARGS"
    exit 1
  fi
fi

if [ "$TRANSPORT" != "sse" ] && [ "$TRANSPORT" != "streamable" ]; then
  echo "Error: transport must be 'sse' or 'streamable'"
  exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass=0
fail=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }
log_info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
log_detail() { echo -e "${CYAN}[DETAIL]${NC} $1"; }

# Print a copy-pasteable curl command when --debug is enabled
# Usage: debug_curl <url> <json_body> [extra_headers...]
debug_curl() {
  [ "$DEBUG" = true ] || return 0
  local url="$1" body="$2"; shift 2
  local pretty_body
  pretty_body=$(echo "$body" | jq '.' 2>/dev/null || echo "$body")
  echo ""
  echo -e "${CYAN}━━━ DEBUG: Copy-paste curl command ━━━${NC}"
  printf "curl -i -X POST '%s' \\\\\n" "$url"
  printf "  -H 'Content-Type: application/json' \\\\\n"
  printf "  -H 'Accept: application/json, text/event-stream' \\\\\n"
  # Print any extra headers (e.g. session id)
  for h in "$@"; do
    printf "  -H '%s' \\\\\n" "$h"
  done
  printf "  -d '\n"
  echo "$pretty_body"
  printf "'\n"
  echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
}

# Print full request + response in debug mode for tools/call
# Usage: debug_tool_io <tool_name> <request_body> <response_body> [http_status]
debug_tool_io() {
  [ "$DEBUG" = true ] || return 0
  local tool_name="$1" req_body="$2" resp_body="$3" http_status="${4:-}"
  echo ""
  echo -e "${CYAN}┌──────────────────────────────────────────────────┐${NC}"
  echo -e "${CYAN}│  tools/call I/O: ${tool_name}${NC}"
  echo -e "${CYAN}├──────────────────────────────────────────────────┤${NC}"
  echo -e "${CYAN}│  REQUEST (arguments sent to tool):${NC}"
  echo -e "${CYAN}└──────────────────────────────────────────────────┘${NC}"
  echo "$req_body" | jq '.params.arguments' 2>/dev/null || echo "$req_body"
  echo ""
  echo -e "${CYAN}┌──────────────────────────────────────────────────┐${NC}"
  if [ -n "$http_status" ]; then
    echo -e "${CYAN}│  RESPONSE (HTTP ${http_status}):${NC}"
  else
    echo -e "${CYAN}│  RESPONSE:${NC}"
  fi
  echo -e "${CYAN}└──────────────────────────────────────────────────┘${NC}"
  echo "$resp_body" | jq '.' 2>/dev/null || echo "$resp_body"
  echo ""
}

assert_status() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$actual" -eq "$expected" ] 2>/dev/null; then
    log_pass "$desc (HTTP $actual)"; ((pass++)) || true
  else
    log_fail "$desc — expected $expected, got $actual"; ((fail++)) || true
  fi
}

assert_json_field() {
  local desc="$1" body="$2" field="$3"
  if echo "$body" | jq -e "$field" >/dev/null 2>&1; then
    log_pass "$desc"; ((pass++)) || true
  else
    log_fail "$desc — field '$field' not found"; ((fail++)) || true
  fi
}

curl_post() {
  local url="$1" data="$2"; shift 2
  local header_args=()
  for h in "${CUSTOM_HEADERS[@]}"; do
    header_args+=(-H "$h")
  done
  curl -s -w "\n%{http_code}" -X POST "$url" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" "${header_args[@]}" "$@" -d "$data"
}

INIT_BODY='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-client","version":"0.1.0"}}}'
TOOLS_LIST_BODY='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

# Global: stores the dynamically built tools/call body after build_tool_call_body is called
TOOL_CALL_BODY=""
TOOL_CALL_NAME=""

parse_response() {
  local result="$1"
  RESP_STATUS=$(echo "$result" | tail -1)
  RESP_BODY=$(echo "$result" | sed '$d')
  # If response is SSE format (contains "data:" lines), extract the JSON from data field
  if echo "$RESP_BODY" | grep -q "^data:"; then
    RESP_BODY=$(echo "$RESP_BODY" | grep "^data:" | head -1 | sed 's/^data: *//')
  fi
}

# ===================== Dynamic Tool Call Builder =====================
# Given the tools/list RESP_BODY, pick a tool and build a tools/call JSON-RPC body.
# Respects USER_TOOL (--tool) and USER_ARGS (--args) overrides.
# For each parameter, generate a sensible default value based on its type.
# Sets global TOOL_CALL_BODY and TOOL_CALL_NAME.
build_tool_call_body() {
  local tools_body="$1"
  local rpc_id="${2:-3}"

  local tool_count
  tool_count=$(echo "$tools_body" | jq '.result.tools | length' 2>/dev/null || echo 0)

  if [ "$tool_count" -eq 0 ]; then
    log_info "No tools discovered, skipping dynamic tool call"
    TOOL_CALL_BODY=""
    TOOL_CALL_NAME=""
    return 1
  fi

  # Select tool: --tool <name> or default to first
  local tool_json
  if [ -n "$USER_TOOL" ]; then
    tool_json=$(echo "$tools_body" | jq -c --arg name "$USER_TOOL" '.result.tools[] | select(.name == $name)' 2>/dev/null | head -1)
    if [ -z "$tool_json" ]; then
      log_fail "--tool '$USER_TOOL' not found in tools/list"
      log_info "Available tools:"
      echo "$tools_body" | jq -r '.result.tools[].name' 2>/dev/null | while read -r t; do echo "  - $t"; done
      TOOL_CALL_BODY=""
      TOOL_CALL_NAME=""
      return 1
    fi
  else
    tool_json=$(echo "$tools_body" | jq -c '.result.tools[0]' 2>/dev/null)
  fi

  TOOL_CALL_NAME=$(echo "$tool_json" | jq -r '.name' 2>/dev/null)
  local schema
  schema=$(echo "$tool_json" | jq -c '.inputSchema // {}' 2>/dev/null)

  log_info "Building dynamic call for tool: ${TOOL_CALL_NAME}"

  # If user provided --args, use it directly (with optional merge)
  local args="{}"
  if [ -n "$USER_ARGS" ]; then
    args="$USER_ARGS"
    log_info "Using user-specified arguments (--args)"
    log_detail "User arguments: $(echo "$args" | jq -c .)"
  else
    # Auto-generate arguments from inputSchema.properties
    local has_properties
    has_properties=$(echo "$schema" | jq 'has("properties")' 2>/dev/null || echo "false")

    if [ "$has_properties" = "true" ]; then
      args=$(echo "$schema" | jq -c '
        .properties as $props |
        (.required // []) as $req |
        reduce ($props | to_entries[]) as $entry (
          {};
          . + {
            ($entry.key): (
              if ($entry.value.type == "string") then
                if ($entry.value.enum // [] | length) > 0 then $entry.value.enum[0]
                elif ($entry.key | test("url|uri|link"; "i")) then "https://example.com"
                elif ($entry.key | test("email"; "i")) then "test@example.com"
                elif ($entry.key | test("name"; "i")) then "test"
                elif ($entry.key | test("message|msg|text|query|content|input|prompt"; "i")) then "hello from test client"
                elif ($entry.key | test("id"; "i")) then "test-id-001"
                elif ($entry.key | test("path|file"; "i")) then "/tmp/test"
                else "test-value"
                end
              elif ($entry.value.type == "number" or $entry.value.type == "integer") then
                if $entry.value.minimum then $entry.value.minimum
                elif $entry.value.default then $entry.value.default
                else 1
                end
              elif ($entry.value.type == "boolean") then true
              elif ($entry.value.type == "array") then []
              elif ($entry.value.type == "object") then {}
              else "test"
              end
            )
          }
        )
      ' 2>/dev/null || echo '{}')

      log_detail "Auto-generated arguments: $(echo "$args" | jq -c .)"
    else
      log_info "Tool has no input schema properties, calling with empty arguments"
    fi
  fi

  TOOL_CALL_BODY=$(jq -n -c \
    --arg name "$TOOL_CALL_NAME" \
    --argjson id "$rpc_id" \
    --argjson args "$args" \
    '{"jsonrpc":"2.0","id":$id,"method":"tools/call","params":{"name":$name,"arguments":$args}}')

  log_detail "Request body: $TOOL_CALL_BODY"
  return 0
}

# ===================== SSE Transport =====================
test_sse() {
  log_info "=== SSE Transport: $URL ==="

  # 1. Start SSE connection in background
  SSE_FILE=$(mktemp)
  SSE_STATUS_FILE=$(mktemp)
  local sse_header_args=()
  for h in "${CUSTOM_HEADERS[@]}"; do
    sse_header_args+=(-H "$h")
  done
  curl -s -N -w "%{http_code}" "${sse_header_args[@]}" "$URL" > "$SSE_FILE" 2>/dev/null &
  SSE_PID=$!
  trap "kill $SSE_PID 2>/dev/null; rm -f $SSE_FILE $SSE_STATUS_FILE" EXIT

  # Wait for endpoint event or auth failure
  local sse_data="" i=0
  while [ -z "$sse_data" ] && [ "$i" -lt 50 ]; do
    sse_data=$(grep -m1 "^data:" "$SSE_FILE" 2>/dev/null | sed 's/^data: *//' || true)
    # Check if connection was rejected (non-SSE response, e.g. 401/403 body)
    if [ -z "$sse_data" ] && [ "$i" -gt 5 ]; then
      # If process already exited and no SSE data, likely auth failure
      if ! kill -0 $SSE_PID 2>/dev/null; then
        local file_content
        file_content=$(cat "$SSE_FILE" 2>/dev/null)
        if echo "$file_content" | grep -qE '^[0-9]{3}$'; then
          local http_code
          http_code=$(echo "$file_content" | grep -oE '[0-9]{3}$' | tail -1)
          log_fail "SSE connection rejected with HTTP $http_code (likely auth required)"
          ((fail++)) || true; return
        fi
        break
      fi
    fi
    [ -z "$sse_data" ] && sleep 0.1
    ((i++)) || true
  done

  if [ -z "$sse_data" ]; then
    log_fail "Cannot connect to SSE endpoint or no data received"
    ((fail++)) || true; return
  fi

  local msg_url="$sse_data"
  if [[ "$msg_url" != http* ]]; then
    msg_url="$(echo "$URL" | grep -oE '^https?://[^/]+')${msg_url}"
  fi
  log_pass "SSE connected, message endpoint: $msg_url"; ((pass++)) || true

  # 2. Initialize
  sse_post_and_read "$msg_url" "$INIT_BODY" 1
  assert_json_field "initialize has result" "$RESP_BODY" ".result"
  assert_json_field "initialize has protocolVersion" "$RESP_BODY" ".result.protocolVersion"

  # 3. tools/list
  sse_post_and_read "$msg_url" "$TOOLS_LIST_BODY" 2
  assert_json_field "tools/list has tools" "$RESP_BODY" ".result.tools"
  print_tools "$RESP_BODY"

  # 4. Dynamic tool call
  local tools_resp="$RESP_BODY"
  if build_tool_call_body "$tools_resp" 3; then
    log_info "--- Tool Call: ${TOOL_CALL_NAME} ---"
    debug_curl "$msg_url" "$TOOL_CALL_BODY"
    local line_before
    line_before=$(wc -l < "$SSE_FILE")
    local http_st
    local tc_header_args=()
    for h in "${CUSTOM_HEADERS[@]}"; do
      tc_header_args+=(-H "$h")
    done
    http_st=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$msg_url" \
      -H "Content-Type: application/json" "${tc_header_args[@]}" \
      -d "$TOOL_CALL_BODY")
    if [ "$http_st" = "202" ] || [ "$http_st" = "200" ]; then
      # Wait for response in SSE stream
      local tool_resp="" wi=0
      while [ "$wi" -lt 50 ]; do
        tool_resp=$(tail -n +"$((line_before+1))" "$SSE_FILE" \
          | grep "^data:" | sed 's/^data: *//' | tr -d '\r' \
          | jq -c "select(.id == 3)" 2>/dev/null | head -1 || true)
        [ -n "$tool_resp" ] && break
        sleep 0.2
        ((wi++)) || true
      done
      if [ -n "$tool_resp" ] && echo "$tool_resp" | jq -e ".result" >/dev/null 2>&1; then
        log_pass "tools/call ${TOOL_CALL_NAME} succeeded"; ((pass++)) || true
        log_detail "Response: $(echo "$tool_resp" | jq -c '.result' 2>/dev/null)"
        debug_tool_io "$TOOL_CALL_NAME" "$TOOL_CALL_BODY" "$tool_resp" "$http_st"
      elif [ -n "$tool_resp" ] && echo "$tool_resp" | jq -e ".error" >/dev/null 2>&1; then
        local err_msg
        err_msg=$(echo "$tool_resp" | jq -r '.error.message // "unknown"' 2>/dev/null)
        log_fail "tools/call ${TOOL_CALL_NAME} returned error: $err_msg"; ((fail++)) || true
        debug_tool_io "$TOOL_CALL_NAME" "$TOOL_CALL_BODY" "$tool_resp" "$http_st"
      else
        log_fail "tools/call ${TOOL_CALL_NAME} — timeout or unexpected response"; ((fail++)) || true
        debug_tool_io "$TOOL_CALL_NAME" "$TOOL_CALL_BODY" "${tool_resp:-<no response>}" "$http_st"
      fi
    else
      log_fail "tools/call ${TOOL_CALL_NAME} POST failed (HTTP $http_st)"; ((fail++)) || true
    fi
  fi

  # 5. Error handling
  log_info "--- Error Handling ---"
  sse_post_and_read "$msg_url" '{"jsonrpc":"2.0","id":99,"method":"nonexistent/method","params":{}}' 99
  if echo "$RESP_BODY" | jq -e ".error" >/dev/null 2>&1; then
    log_pass "Non-existent method returns error"; ((pass++)) || true
  else
    log_info "Non-existent method: no JSON-RPC error in SSE stream"
  fi

  # Cleanup
  kill $SSE_PID 2>/dev/null || true
  rm -f "$SSE_FILE"
  trap - EXIT
}

# SSE helper: POST message then read response from SSE stream by JSON-RPC id
sse_post_and_read() {
  local url="$1" data="$2" rpc_id="$3"
  local line_before
  line_before=$(wc -l < "$SSE_FILE")

  # POST and capture HTTP status code
  local header_args=()
  for h in "${CUSTOM_HEADERS[@]}"; do
    header_args+=(-H "$h")
  done
  local post_status
  post_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$url" \
    -H "Content-Type: application/json" "${header_args[@]}" -d "$data")

  # If POST itself failed (non-2xx), report immediately without waiting for SSE stream
  if [ "$post_status" -ge 400 ] 2>/dev/null; then
    RESP_BODY="{\"error\":{\"code\":$post_status,\"message\":\"HTTP $post_status\"}}"
    log_fail "POST returned HTTP $post_status (auth rejected or server error)"; ((fail++)) || true
    return
  fi

  # Wait for response in SSE stream (up to 10s)
  RESP_BODY=""
  local i=0
  while [ "$i" -lt 50 ]; do
    RESP_BODY=$(tail -n +"$((line_before+1))" "$SSE_FILE" \
      | grep "^data:" | sed 's/^data: *//' | tr -d '\r' \
      | jq -c "select(.id == $rpc_id)" 2>/dev/null | head -1 || true)
    [ -n "$RESP_BODY" ] && break
    sleep 0.2
    ((i++)) || true
  done

  if [ -n "$RESP_BODY" ]; then
    log_pass "Received response for id=$rpc_id"; ((pass++)) || true
  else
    log_fail "Timeout waiting for response id=$rpc_id"; ((fail++)) || true
  fi
}

# ===================== Streamable HTTP Transport =====================
test_streamable() {
  log_info "=== Streamable HTTP Transport: $URL ==="

  # 1. Initialize
  parse_response "$(curl_post "$URL" "$INIT_BODY")"
  assert_status "initialize" 200 "$RESP_STATUS"
  assert_json_field "initialize has result" "$RESP_BODY" ".result"
  assert_json_field "has protocolVersion" "$RESP_BODY" ".result.protocolVersion"

  # Extract session id from a separate HEAD-like call
  local session_args=()
  local headers
  headers=$(curl -s -D - -o /dev/null -X POST "$URL" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d "$INIT_BODY" 2>/dev/null)
  local sid
  sid=$(echo "$headers" | grep -i "mcp-session-id" | head -1 | sed 's/.*: *//;s/\r//')
  if [ -n "$sid" ]; then
    log_pass "Got session id: $sid"; ((pass++)) || true
    session_args=(-H "Mcp-Session-Id: ${sid}")
  fi

  # 2. tools/list
  parse_response "$(curl_post "$URL" "$TOOLS_LIST_BODY" "${session_args[@]}")"
  assert_status "tools/list" 200 "$RESP_STATUS"
  assert_json_field "tools/list has tools" "$RESP_BODY" ".result.tools"
  print_tools "$RESP_BODY"

  # 3. Dynamic tool call
  local tools_resp="$RESP_BODY"
  if build_tool_call_body "$tools_resp" 3; then
    log_info "--- Tool Call: ${TOOL_CALL_NAME} ---"
    # Build extra header strings for debug output
    local debug_extra_headers=()
    for h in "${session_args[@]}"; do
      # session_args are like -H "Mcp-Session-Id: xxx", skip the -H flag
      if [ "$h" != "-H" ]; then
        debug_extra_headers+=("$h")
      fi
    done
    debug_curl "$URL" "$TOOL_CALL_BODY" "${debug_extra_headers[@]}"
    parse_response "$(curl_post "$URL" "$TOOL_CALL_BODY" "${session_args[@]}")"
    if [ "$RESP_STATUS" -eq 200 ] 2>/dev/null && echo "$RESP_BODY" | jq -e ".result" >/dev/null 2>&1; then
      log_pass "tools/call ${TOOL_CALL_NAME} succeeded (HTTP $RESP_STATUS)"; ((pass++)) || true
      log_detail "Response: $(echo "$RESP_BODY" | jq -c '.result' 2>/dev/null)"
      debug_tool_io "$TOOL_CALL_NAME" "$TOOL_CALL_BODY" "$RESP_BODY" "$RESP_STATUS"
    elif echo "$RESP_BODY" | jq -e ".error" >/dev/null 2>&1; then
      local err_msg
      err_msg=$(echo "$RESP_BODY" | jq -r '.error.message // "unknown"' 2>/dev/null)
      log_fail "tools/call ${TOOL_CALL_NAME} returned error: $err_msg (HTTP $RESP_STATUS)"; ((fail++)) || true
      debug_tool_io "$TOOL_CALL_NAME" "$TOOL_CALL_BODY" "$RESP_BODY" "$RESP_STATUS"
    else
      log_fail "tools/call ${TOOL_CALL_NAME} — unexpected response (HTTP $RESP_STATUS)"; ((fail++)) || true
      debug_tool_io "$TOOL_CALL_NAME" "$TOOL_CALL_BODY" "$RESP_BODY" "$RESP_STATUS"
    fi
  fi

  # 4. Error handling
  test_error "$URL" "${session_args[@]}"
}

# ===================== Common Tests =====================
print_tools() {
  local body="$1"
  local tool_count
  tool_count=$(echo "$body" | jq '.result.tools | length' 2>/dev/null || echo 0)
  if [ "$tool_count" -gt 0 ]; then
    log_info "Discovered $tool_count tool(s):"
    echo "$body" | jq -r '.result.tools[] | "  - \(.name): \(.description // "no description")"' 2>/dev/null || true
    # Print parameter summary for each tool
    echo "$body" | jq -r '
      .result.tools[] |
      "    params: " + (
        if .inputSchema.properties then
          [.inputSchema.properties | to_entries[] |
            .key + "(" + (.value.type // "any") + ")" +
            if (.value | has("enum")) then "[" + (.value.enum | join(",")) + "]" else "" end
          ] | join(", ")
        else "none"
        end
      ) + (
        if .inputSchema.required then
          "  required: [" + (.inputSchema.required | join(", ")) + "]"
        else ""
        end
      )
    ' 2>/dev/null || true
  fi
}

test_error() {
  local url="$1"; shift
  log_info "--- Error Handling ---"

  # Non-existent method
  parse_response "$(curl_post "$url" '{"jsonrpc":"2.0","id":99,"method":"nonexistent/method","params":{}}' "$@")"
  if echo "$RESP_BODY" | jq -e ".error" >/dev/null 2>&1; then
    log_pass "Non-existent method returns error"; ((pass++)) || true
  else
    log_info "Non-existent method: no JSON-RPC error (HTTP $RESP_STATUS)"
  fi

  # Invalid JSON
  local resp
  resp=$(curl -s -w "\n%{http_code}" -X POST "$url" -H "Content-Type: application/json" "$@" -d '{bad}')
  local st=$(echo "$resp" | tail -1)
  if [ "$st" -ge 400 ] 2>/dev/null; then
    log_pass "Invalid JSON rejected (HTTP $st)"; ((pass++)) || true
  else
    log_info "Invalid JSON not rejected (HTTP $st)"
  fi
}

# ===================== Main =====================
echo "============================================"
echo " MCP Server Client Test"
echo " Transport: ${TRANSPORT}"
echo " URL:       ${URL}"
if [ -n "$USER_TOOL" ]; then
echo " Tool:      ${USER_TOOL}"
fi
if [ -n "$USER_ARGS" ]; then
echo " Args:      ${USER_ARGS}"
fi
if [ "${#CUSTOM_HEADERS[@]}" -gt 0 ]; then
echo " Headers:   ${#CUSTOM_HEADERS[@]} custom header(s)"
for h in "${CUSTOM_HEADERS[@]}"; do
echo "             $h"
done
fi
if [ "$DEBUG" = true ]; then
echo " Debug:     ON (curl commands will be printed)"
fi
echo "============================================"
echo ""

if [ "$TRANSPORT" = "sse" ]; then
  test_sse
else
  test_streamable
fi

echo ""
echo "============================================"
echo -e " Results: ${GREEN}${pass} passed${NC}, ${RED}${fail} failed${NC}"
echo "============================================"

[ "$fail" -eq 0 ] && exit 0 || exit 1
