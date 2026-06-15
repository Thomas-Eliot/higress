#!/bin/bash
# Phase 1: Key-Auth 分片模式回归测试 (apsara-main / v2.1.12)
# 基于回归计划 test-plan.md，覆盖 US-1~US-6 (不含 US-7.1 并发)
# 环境: ls-test, admin: aigateway-system-dev

set -uo pipefail

ADMIN="http://8.137.60.56"
GATEWAY="http://8.137.183.111"
GW_ID="i-py7tc8185oidqjoqdf13"
NS="ls-test"
COOKIE="/tmp/test-cookies-regression.txt"
ROUTE_ID="echo-server"
ROUTE_HOST=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; FAILURES=$((FAILURES+1)); }
info() { echo -e "${YELLOW}INFO${NC}: $1"; }
section() { echo ""; echo "========================================"; echo "  $1"; echo "========================================"; }

FAILURES=0

api() {
  curl -s -b "$COOKIE" -X POST "${ADMIN}${1}" -H 'Content-Type: application/json' -d "$2"
}

json_field() {
  python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('$1',''))"
}

json_code() {
  python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('code',''))"
}

gateway_code() {
  curl -s --connect-timeout 5 --max-time 8 -o /dev/null -w '%{http_code}' "$@"
}

wait_published() {
  local max_wait=${1:-15}
  info "Waiting for config to propagate (${max_wait}s)..."
  sleep "$max_wait"
}

# ============================================================
section "Step 0: Login"
# ============================================================
curl -s -c "$COOKIE" -X POST "$ADMIN/user/login" -H 'Content-Type: application/json' \
  -d '{"account":"admin","password":"Ab123456"}' > /dev/null
echo "Login done"

# ============================================================
section "US-1.1: Create consumer"
# ============================================================
TS=$(date +%s)
RESULT=$(api "/application/createApp" "{\"gwInstanceId\":\"$GW_ID\",\"appName\":\"regression-consumer-a\",\"authType\":5,\"key\":\"regkey-aaa-${TS}\",\"apiKeyLocationType\":\"BEARER\"}")
CODE=$(echo "$RESULT" | json_code)
if [ "$CODE" = "200" ]; then
  APP_ID_A=$(echo "$RESULT" | json_field "data")
  KEY_A=$(echo "$RESULT" | python3 -c "import sys,json;print(json.load(sys.stdin).get('data',''))" 2>/dev/null)
  pass "US-1.1 Created consumer-a, appId=$APP_ID_A"
else
  fail "US-1.1 Create consumer-a failed: $RESULT"
  APP_ID_A=""
fi

CONSUMER_A_KEY="regkey-aaa-${TS}"
info "Consumer-a key: $CONSUMER_A_KEY"

# Create second consumer
CONSUMER_B_KEY="regkey-bbb-${TS}"
RESULT2=$(api "/application/createApp" "{\"gwInstanceId\":\"$GW_ID\",\"appName\":\"regression-consumer-b\",\"authType\":5,\"key\":\"$CONSUMER_B_KEY\",\"apiKeyLocationType\":\"BEARER\"}")
CODE2=$(echo "$RESULT2" | json_code)
if [ "$CODE2" = "200" ]; then
  APP_ID_B=$(echo "$RESULT2" | json_field "data")
  pass "US-1.1 Created consumer-b, appId=$APP_ID_B"
else
  fail "US-1.1 Create consumer-b failed: $RESULT2"
  APP_ID_B=""
fi

# ============================================================
section "US-5.1: Async publish verification"
# ============================================================
sleep 5
RESULT=$(api "/application/listApps" "{\"gwInstanceId\":\"$GW_ID\",\"current\":1,\"size\":10}")
PUB_STATUS=$(echo "$RESULT" | python3 -c "
import sys,json
d=json.load(sys.stdin)
records=d.get('data',{}).get('records',[])
statuses=[r.get('publishStatus','?') for r in records if r.get('appName','').startswith('regression-')]
print(','.join(statuses))
")
if echo "$PUB_STATUS" | grep -q "PUBLISHED"; then
  pass "US-5.1 Async publish OK: $PUB_STATUS"
else
  info "US-5.1 Publish status: $PUB_STATUS (may still be PENDING)"
fi

# ============================================================
section "US-1.2: List consumers"
# ============================================================
RESULT=$(api "/application/listApps" "{\"gwInstanceId\":\"$GW_ID\",\"current\":1,\"size\":10}")
TOTAL=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('data',{}).get('total',0))")
HAS_PUB=$(echo "$RESULT" | python3 -c "
import sys,json
d=json.load(sys.stdin)
records=d.get('data',{}).get('records',[])
print('yes' if records and 'publishStatus' in records[0] else 'no')
")
if [ "$TOTAL" -ge "2" ] && [ "$HAS_PUB" = "yes" ]; then
  pass "US-1.2 List OK, total=$TOTAL, publishStatus present"
else
  fail "US-1.2 List issue, total=$TOTAL, hasPublishStatus=$HAS_PUB"
fi

# ============================================================
section "US-1.5: Duplicate key"
# ============================================================
RESULT=$(api "/application/createApp" "{\"gwInstanceId\":\"$GW_ID\",\"appName\":\"regression-dup\",\"authType\":5,\"key\":\"$CONSUMER_B_KEY\",\"apiKeyLocationType\":\"BEARER\"}")
CODE=$(echo "$RESULT" | json_code)
if [ "$CODE" != "200" ]; then
  MSG=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('msg','') or d.get('message',''))")
  pass "US-1.5 Duplicate key rejected: $MSG"
else
  fail "US-1.5 Duplicate key was NOT rejected"
fi

# ============================================================
section "US-3.1: Enable key-auth for route"
# ============================================================
RESULT=$(api "/strategyConfig/createStrategyConfig" "{\"gwInstanceId\":\"$GW_ID\",\"strategyName\":\"key-auth\",\"routeIds\":[\"$ROUTE_ID\"],\"config\":{}}")
CODE=$(echo "$RESULT" | json_code)
if [ "$CODE" = "200" ]; then
  STRATEGY_ID=$(echo "$RESULT" | json_field "data")
  pass "US-3.1 Enabled key-auth for $ROUTE_ID, strategyId=$STRATEGY_ID"
else
  MSG=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('msg','') or d.get('message',''))")
  fail "US-3.1 Enable key-auth failed: $MSG"
  STRATEGY_ID=""
fi

# ============================================================
section "US-3.2: Route plugin list visible"
# ============================================================
RESULT=$(api "/strategyConfig/listStrategyConfigs" "{\"gwInstanceId\":\"$GW_ID\",\"scope\":{\"routeId\":\"$ROUTE_ID\"}}")
CODE=$(echo "$RESULT" | json_code)
SC_TOTAL=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('data',{}).get('total',0))" 2>/dev/null || echo "0")
if [ "$CODE" = "200" ] && [ "$SC_TOTAL" -ge "1" ]; then
  pass "US-3.2 Route plugin list visible, total=$SC_TOTAL"
else
  fail "US-3.2 Route plugin list issue: code=$CODE, total=$SC_TOTAL"
fi

# ============================================================
section "US-2.1: Authorize consumer-a to route"
# ============================================================
RESULT=$(api "/applicationauth/createAppAuthByRoute" "{\"gwInstanceId\":\"$GW_ID\",\"appId\":\"$APP_ID_A\",\"grantTargetId\":\"$ROUTE_ID\",\"authStatus\":1,\"grantType\":\"ROUTER\"}")
CODE=$(echo "$RESULT" | json_code)
if [ "$CODE" = "200" ]; then
  AUTH_ID_A=$(echo "$RESULT" | json_field "data")
  pass "US-2.1 Authorized consumer-a to $ROUTE_ID, authId=$AUTH_ID_A"
else
  MSG=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('msg','') or d.get('message',''))")
  fail "US-2.1 Authorization failed: $MSG"
fi

# ============================================================
section "US-4.1: Full publish"
# ============================================================
RESULT=$(api "/application/fullPublish" "{\"gwInstanceId\":\"$GW_ID\"}")
CODE=$(echo "$RESULT" | json_code)
if [ "$CODE" = "200" ]; then
  pass "US-4.1 Full publish OK"
else
  MSG=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('msg','') or d.get('message',''))")
  fail "US-4.1 Full publish failed: $MSG"
fi

wait_published 15

# ============================================================
section "US-6: Shard data correctness"
# ============================================================
# 6.2 Shard ConfigMaps
SHARD_COUNT=$(kubectl get configmap -n $NS -l higress.io/biz-type=hi-key-auth-shard --no-headers 2>/dev/null | wc -l | tr -d ' ')
if [ "$SHARD_COUNT" -gt "0" ]; then
  pass "US-6.2 Shard ConfigMaps exist, count=$SHARD_COUNT"
else
  fail "US-6.2 No shard ConfigMaps found"
fi

# 6.3 route-switches
RS_EXISTS=$(kubectl get configmap hi-key-auth-route-switches -n $NS --no-headers 2>/dev/null | wc -l | tr -d ' ')
if [ "$RS_EXISTS" -gt "0" ]; then
  pass "US-6.3 route-switches ConfigMap exists"
else
  info "US-6.3 route-switches not found (may not be enabled)"
fi

# 6.4 WasmPlugin CR
WP_EXISTS=$(kubectl get wasmplugin key-auth.internal -n $NS --no-headers 2>/dev/null | wc -l | tr -d ' ')
if [ "$WP_EXISTS" -gt "0" ]; then
  REFS_COUNT=$(kubectl get wasmplugin key-auth.internal -n $NS -o json 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
refs=d.get('spec',{}).get('resourceRefs',[])
print(len(refs) if refs else 0)
")
  pass "US-6.4 WasmPlugin CR exists, resourceRefs=$REFS_COUNT"
else
  fail "US-6.4 WasmPlugin CR not found"
fi

# ============================================================
section "US-2.4/2.5/2.6: Data plane auth verification"
# ============================================================
# 2.4 Authorized key
HTTP_CODE=$(gateway_code -H "Authorization: Bearer $CONSUMER_A_KEY" "$GATEWAY/echo")
if [ "$HTTP_CODE" = "200" ]; then
  pass "US-2.4 Authorized key OK (HTTP $HTTP_CODE)"
else
  fail "US-2.4 Authorized key failed (HTTP $HTTP_CODE, expected 200)"
fi

# 2.5 Unauthorized consumer key
HTTP_CODE=$(gateway_code -H "Authorization: Bearer $CONSUMER_B_KEY" "$GATEWAY/echo")
if [ "$HTTP_CODE" = "403" ]; then
  pass "US-2.5 Unauthorized key rejected (HTTP $HTTP_CODE)"
else
  fail "US-2.5 Unauthorized key got HTTP $HTTP_CODE (expected 403)"
fi

# 2.6 No key
HTTP_CODE=$(gateway_code "$GATEWAY/echo")
if [ "$HTTP_CODE" = "401" ]; then
  pass "US-2.6 No key rejected (HTTP $HTTP_CODE)"
else
  fail "US-2.6 No key got HTTP $HTTP_CODE (expected 401)"
fi

# ============================================================
section "US-1.3: Update consumer credential"
# ============================================================
NEW_KEY="regkey-aaa-updated-$(date +%s)"
RESULT=$(api "/application/modifyApp" "{\"gwInstanceId\":\"$GW_ID\",\"appId\":\"$APP_ID_A\",\"appName\":\"regression-consumer-a\",\"authType\":5,\"key\":\"$NEW_KEY\",\"apiKeyLocationType\":\"BEARER\"}")
CODE=$(echo "$RESULT" | json_code)
if [ "$CODE" = "200" ]; then
  pass "US-1.3 Updated credential OK"
else
  fail "US-1.3 Update failed: $RESULT"
fi

wait_published 10

# Old key should fail
HTTP_CODE=$(gateway_code -H "Authorization: Bearer $CONSUMER_A_KEY" "$GATEWAY/echo")
if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
  pass "US-1.3 Old key invalidated (HTTP $HTTP_CODE)"
else
  fail "US-1.3 Old key still works (HTTP $HTTP_CODE, expected 401/403)"
fi

# New key should work
HTTP_CODE=$(gateway_code -H "Authorization: Bearer $NEW_KEY" "$GATEWAY/echo")
if [ "$HTTP_CODE" = "200" ]; then
  pass "US-1.3 New key works (HTTP $HTTP_CODE)"
else
  fail "US-1.3 New key failed (HTTP $HTTP_CODE, expected 200)"
fi
CONSUMER_A_KEY="$NEW_KEY"

# ============================================================
section "US-3.3: Disable route key-auth"
# ============================================================
if [ -n "$STRATEGY_ID" ]; then
  RESULT=$(api "/strategyConfig/modifyStrategyConfigStatus" "{\"gwInstanceId\":\"$GW_ID\",\"strategyConfigId\":\"$STRATEGY_ID\",\"isOpen\":false}")
  CODE=$(echo "$RESULT" | json_code)
  if [ "$CODE" = "200" ]; then
    pass "US-3.3 Disabled key-auth"
  else
    fail "US-3.3 Disable failed: $RESULT"
  fi

  wait_published 10

  HTTP_CODE=$(gateway_code "$GATEWAY/echo")
  if [ "$HTTP_CODE" = "200" ]; then
    pass "US-3.3 No key passes after disable (HTTP $HTTP_CODE)"
  else
    fail "US-3.3 No key still rejected after disable (HTTP $HTTP_CODE)"
  fi
fi

# ============================================================
section "US-3.4: Re-enable key-auth"
# ============================================================
if [ -n "$STRATEGY_ID" ]; then
  RESULT=$(api "/strategyConfig/modifyStrategyConfigStatus" "{\"gwInstanceId\":\"$GW_ID\",\"strategyConfigId\":\"$STRATEGY_ID\",\"isOpen\":true}")
  CODE=$(echo "$RESULT" | json_code)
  if [ "$CODE" = "200" ]; then
    pass "US-3.4 Re-enabled key-auth"
  else
    fail "US-3.4 Re-enable failed: $RESULT"
  fi

  wait_published 10

  HTTP_CODE=$(gateway_code "$GATEWAY/echo")
  if [ "$HTTP_CODE" = "401" ]; then
    pass "US-3.4 No key rejected after re-enable (HTTP $HTTP_CODE)"
  else
    fail "US-3.4 No key not rejected after re-enable (HTTP $HTTP_CODE)"
  fi
fi

# ============================================================
section "US-2.7: Authorize to non-existent route"
# ============================================================
RESULT=$(api "/applicationauth/createAppAuthByRoute" "{\"gwInstanceId\":\"$GW_ID\",\"appId\":\"$APP_ID_A\",\"grantTargetId\":\"non-existent-route-xyz\",\"authStatus\":1,\"grantType\":\"ROUTER\"}")
CODE=$(echo "$RESULT" | json_code)
if [ "$CODE" != "200" ]; then
  MSG=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('msg','') or d.get('message',''))")
  pass "US-2.7 Non-existent route rejected: $MSG"
else
  fail "US-2.7 Non-existent route was NOT rejected"
fi

# ============================================================
section "US-3.5: Delete route key-auth plugin"
# ============================================================
if [ -n "$STRATEGY_ID" ]; then
  RESULT=$(api "/strategyConfig/deleteStrategyConfig" "{\"gwInstanceId\":\"$GW_ID\",\"strategyConfigId\":\"$STRATEGY_ID\"}")
  CODE=$(echo "$RESULT" | json_code)
  if [ "$CODE" = "200" ]; then
    pass "US-3.5 Deleted key-auth plugin"
  else
    fail "US-3.5 Delete failed: $RESULT"
  fi
fi

# ============================================================
section "US-3.6: Plugin not visible after delete"
# ============================================================
RESULT=$(api "/strategyConfig/listStrategyConfigs" "{\"gwInstanceId\":\"$GW_ID\",\"scope\":{\"routeId\":\"$ROUTE_ID\"}}")
SC_TOTAL=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('data',{}).get('total',0))" 2>/dev/null || echo "0")
if [ "$SC_TOTAL" = "0" ]; then
  pass "US-3.6 Plugin not visible after delete, total=0"
else
  fail "US-3.6 Plugin still visible, total=$SC_TOTAL"
fi

# ============================================================
section "US-3.7: Idempotent delete"
# ============================================================
if [ -n "$STRATEGY_ID" ]; then
  RESULT=$(api "/strategyConfig/deleteStrategyConfig" "{\"gwInstanceId\":\"$GW_ID\",\"strategyConfigId\":\"$STRATEGY_ID\"}")
  CODE=$(echo "$RESULT" | json_code)
  if [ "$CODE" != "500" ]; then
    pass "US-3.7 Idempotent delete OK (code=$CODE)"
  else
    fail "US-3.7 Idempotent delete returned 500"
  fi
fi

# ============================================================
section "US-1.4: Delete consumer"
# ============================================================
if [ -n "$APP_ID_B" ]; then
  RESULT=$(api "/application/deleteApp" "{\"gwInstanceId\":\"$GW_ID\",\"appId\":\"$APP_ID_B\"}")
  CODE=$(echo "$RESULT" | json_code)
  if [ "$CODE" = "200" ]; then
    pass "US-1.4 Deleted consumer-b"
  else
    fail "US-1.4 Delete consumer-b failed: $RESULT"
  fi
fi

# ============================================================
section "Cleanup"
# ============================================================
if [ -n "$APP_ID_A" ]; then
  api "/application/deleteApp" "{\"gwInstanceId\":\"$GW_ID\",\"appId\":\"$APP_ID_A\"}" > /dev/null 2>&1
  info "Cleaned up consumer-a"
fi

# ============================================================
section "RESULTS"
# ============================================================
echo ""
if [ "$FAILURES" -eq 0 ]; then
  echo -e "${GREEN}All tests passed!${NC}"
else
  echo -e "${RED}$FAILURES test(s) FAILED${NC}"
fi
echo ""
echo "Completed: $(date '+%Y-%m-%d %H:%M:%S')"
exit $FAILURES
