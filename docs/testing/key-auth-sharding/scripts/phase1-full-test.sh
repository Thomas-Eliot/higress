#!/bin/bash
# Phase 1: Key-Auth 分片模式全量功能验证
# 测试环境: ls-test 实例 (2.1.12)
# 日期: 2026-05-19

set -euo pipefail

ADMIN="http://8.137.83.34"
GATEWAY="http://8.156.87.83"
GW_ID="i-lci63hlysglgtpry1sjq"
COOKIE="/tmp/test-cookies.txt"
ROUTE_ID="ls-test-echo"
ROUTE_ID_2="fd"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✅ PASS${NC}: $1"; }
fail() { echo -e "${RED}❌ FAIL${NC}: $1"; FAILURES=$((FAILURES+1)); }
info() { echo -e "${YELLOW}ℹ️  INFO${NC}: $1"; }
section() { echo ""; echo "========================================"; echo "  $1"; echo "========================================"; }

FAILURES=0

api() {
  local path="$1"
  local data="$2"
  curl -s -b "$COOKIE" -X POST "${ADMIN}${path}" -H 'Content-Type: application/json' -d "$data"
}

gateway_code() {
  curl -s --connect-timeout 5 --max-time 8 -o /dev/null -w '%{http_code}' "$@"
}

# ============================================================
section "Step 0: 登录"
# ============================================================
curl -s -c "$COOKIE" -X POST "$ADMIN/user/login" -H 'Content-Type: application/json' \
  -d '{"account":"admin","password":"Ab123456?"}' > /dev/null
echo "登录完成"

# ============================================================
section "US-1.1: 创建消费者"
# ============================================================
RESULT=$(api "/application/createApp" "{\"gwInstanceId\":\"$GW_ID\",\"appName\":\"test-consumer-a\",\"authType\":5,\"key\":\"key-phase1-aaa\",\"apiKeyLocationType\":\"BEARER\"}")
CODE=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('code',''))")
if [ "$CODE" = "200" ]; then
  APP_ID_A=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['data'])")
  pass "US-1.1 创建消费者 test-consumer-a 成功, appId=$APP_ID_A"
else
  fail "US-1.1 创建消费者失败: $RESULT"
  APP_ID_A=""
fi

# 创建第二个消费者用于后续测试
RESULT2=$(api "/application/createApp" "{\"gwInstanceId\":\"$GW_ID\",\"appName\":\"test-consumer-b\",\"authType\":5,\"key\":\"key-phase1-bbb\",\"apiKeyLocationType\":\"BEARER\"}")
CODE2=$(echo "$RESULT2" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('code',''))")
if [ "$CODE2" = "200" ]; then
  APP_ID_B=$(echo "$RESULT2" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['data'])")
  pass "US-1.1 创建消费者 test-consumer-b 成功, appId=$APP_ID_B"
else
  fail "US-1.1 创建消费者 test-consumer-b 失败: $RESULT2"
  APP_ID_B=""
fi

# 等待异步发布完成
info "等待异步发布 (5s)..."
sleep 5

# ============================================================
section "US-5.1: 验证异步发布状态"
# ============================================================
RESULT=$(api "/application/listApps" "{\"gwInstanceId\":\"$GW_ID\",\"current\":1,\"size\":10}")
PUB_STATUS=$(echo "$RESULT" | python3 -c "
import sys,json
d=json.load(sys.stdin)
records=d['data']['records']
statuses=[r.get('publishStatus','?') for r in records]
print(','.join(statuses))
")
if echo "$PUB_STATUS" | grep -q "PUBLISHED"; then
  pass "US-5.1 异步发布成功, 状态: $PUB_STATUS"
else
  info "US-5.1 发布状态: $PUB_STATUS (可能仍在 PENDING)"
fi

# ============================================================
section "US-1.2: 查询消费者列表"
# ============================================================
RESULT=$(api "/application/listApps" "{\"gwInstanceId\":\"$GW_ID\",\"current\":1,\"size\":10}")
TOTAL=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['data']['total'])")
HAS_PUB_STATUS=$(echo "$RESULT" | python3 -c "
import sys,json
d=json.load(sys.stdin)
records=d['data']['records']
print('yes' if records and 'publishStatus' in records[0] else 'no')
")
if [ "$TOTAL" = "2" ] && [ "$HAS_PUB_STATUS" = "yes" ]; then
  pass "US-1.2 查询列表成功, total=$TOTAL, publishStatus字段存在"
else
  fail "US-1.2 查询列表异常, total=$TOTAL, hasPublishStatus=$HAS_PUB_STATUS"
fi

# ============================================================
section "US-1.5: 创建重复 key"
# ============================================================
RESULT=$(api "/application/createApp" "{\"gwInstanceId\":\"$GW_ID\",\"appName\":\"test-consumer-dup\",\"authType\":5,\"key\":\"key-phase1-aaa\",\"apiKeyLocationType\":\"BEARER\"}")
CODE=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('code',''))")
MSG=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('msg','') or d.get('message',''))")
if [ "$CODE" != "200" ]; then
  pass "US-1.5 重复 key 被拒绝: $MSG"
else
  fail "US-1.5 重复 key 未被拒绝"
fi

# ============================================================
section "US-3.1: 为路由启用 key-auth 插件"
# ============================================================
RESULT=$(api "/strategyConfig/createStrategyConfig" "{\"gwInstanceId\":\"$GW_ID\",\"strategyName\":\"key-auth\",\"routeIds\":[\"$ROUTE_ID\"],\"config\":{}}")
CODE=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('code',''))")
if [ "$CODE" = "200" ]; then
  STRATEGY_ID=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('data',''))")
  pass "US-3.1 路由 $ROUTE_ID 启用 key-auth 成功, strategyConfigId=$STRATEGY_ID"
else
  MSG=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('msg','') or d.get('message',''))")
  fail "US-3.1 启用 key-auth 失败: $MSG"
  STRATEGY_ID=""
fi

# ============================================================
section "US-2.1: 授权 consumer-a 到路由"
# ============================================================
RESULT=$(api "/applicationauth/createAppAuthByRoute" "{\"gwInstanceId\":\"$GW_ID\",\"appId\":\"$APP_ID_A\",\"grantTargetId\":\"$ROUTE_ID\",\"authStatus\":1,\"grantType\":\"ROUTER\"}")
CODE=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('code',''))")
if [ "$CODE" = "200" ]; then
  AUTH_ID_A=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('data',''))")
  pass "US-2.1 授权 consumer-a 到路由 $ROUTE_ID 成功, authId=$AUTH_ID_A"
else
  MSG=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('msg','') or d.get('message',''))")
  fail "US-2.1 授权失败: $MSG"
fi

# ============================================================
section "US-4.1: 全量发布"
# ============================================================
RESULT=$(api "/application/fullPublish" "{\"gwInstanceId\":\"$GW_ID\"}")
CODE=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('code',''))")
if [ "$CODE" = "200" ]; then
  pass "US-4.1 全量发布成功"
else
  MSG=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('msg','') or d.get('message',''))")
  fail "US-4.1 全量发布失败: $MSG"
fi

info "等待 Controller 推送配置 (15s)..."
sleep 15

# ============================================================
section "US-6: 分片数据正确性验证"
# ============================================================
# 6.2 检查分片 ConfigMap
SHARD_COUNT=$(kubectl get configmap -n ls-test -l higress.io/biz-type=hi-key-auth-shard --no-headers 2>/dev/null | wc -l | tr -d ' ')
if [ "$SHARD_COUNT" -gt "0" ]; then
  pass "US-6.2 分片 ConfigMap 存在, 数量=$SHARD_COUNT"
else
  fail "US-6.2 未找到分片 ConfigMap"
fi

# 6.3 检查 route-switches ConfigMap
RS_EXISTS=$(kubectl get configmap hi-key-auth-route-switches -n ls-test --no-headers 2>/dev/null | wc -l | tr -d ' ')
if [ "$RS_EXISTS" -gt "0" ]; then
  pass "US-6.3 route-switches ConfigMap 存在"
else
  info "US-6.3 route-switches ConfigMap 不存在 (可能路由开关未启用)"
fi

# 6.4 检查 WasmPlugin CR
WP_EXISTS=$(kubectl get wasmplugin key-auth.internal -n ls-test --no-headers 2>/dev/null | wc -l | tr -d ' ')
if [ "$WP_EXISTS" -gt "0" ]; then
  REFS_COUNT=$(kubectl get wasmplugin key-auth.internal -n ls-test -o json 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
refs=d.get('spec',{}).get('resourceRefs',[])
print(len(refs) if refs else 0)
")
  pass "US-6.4 WasmPlugin CR 存在, resourceRefs 数量=$REFS_COUNT"
else
  fail "US-6.4 WasmPlugin CR 不存在"
fi

# 检查分片 ConfigMap 中是否包含 consumer
info "检查分片 ConfigMap 内容..."
for cm in $(kubectl get configmap -n ls-test -l higress.io/biz-type=hi-key-auth-shard -o name 2>/dev/null | head -5); do
  CONSUMERS=$(kubectl get $cm -n ls-test -o jsonpath='{.data.consumers}' 2>/dev/null | head -3)
  if [ -n "$CONSUMERS" ]; then
    info "$cm 包含 consumers 数据"
  fi
  MATCH_RULES=$(kubectl get $cm -n ls-test -o jsonpath='{.data.matchRules}' 2>/dev/null | head -3)
  if [ -n "$MATCH_RULES" ]; then
    info "$cm 包含 matchRules 数据"
  fi
done

# ============================================================
section "US-2.4/2.5/2.6: 数据面鉴权验证"
# ============================================================
# 2.4 已授权 key
HTTP_CODE=$(gateway_code -H "Authorization: Bearer key-phase1-aaa" "$GATEWAY/")
if [ "$HTTP_CODE" = "200" ]; then
  pass "US-2.4 已授权 key 鉴权通过 (HTTP $HTTP_CODE)"
else
  fail "US-2.4 已授权 key 鉴权失败 (HTTP $HTTP_CODE, 期望 200)"
fi

# 2.5 未授权 consumer 的 key (consumer-b 未授权到该路由)
HTTP_CODE=$(gateway_code -H "Authorization: Bearer key-phase1-bbb" "$GATEWAY/")
if [ "$HTTP_CODE" = "403" ]; then
  pass "US-2.5 未授权 key 被拒绝 (HTTP $HTTP_CODE)"
else
  fail "US-2.5 未授权 key 返回异常 (HTTP $HTTP_CODE, 期望 403)"
fi

# 2.6 无 key
HTTP_CODE=$(gateway_code "$GATEWAY/")
if [ "$HTTP_CODE" = "401" ]; then
  pass "US-2.6 无 key 被拒绝 (HTTP $HTTP_CODE)"
else
  fail "US-2.6 无 key 返回异常 (HTTP $HTTP_CODE, 期望 401)"
fi

# ============================================================
section "US-1.3: 更新消费者 (修改 credential)"
# ============================================================
RESULT=$(api "/application/modifyApp" "{\"gwInstanceId\":\"$GW_ID\",\"appId\":\"$APP_ID_A\",\"appName\":\"test-consumer-a\",\"authType\":5,\"key\":\"key-phase1-aaa-new\",\"apiKeyLocationType\":\"BEARER\"}")
CODE=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('code',''))")
if [ "$CODE" = "200" ]; then
  pass "US-1.3 更新消费者 credential 成功"
else
  MSG=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('msg','') or d.get('message',''))")
  fail "US-1.3 更新消费者失败: $MSG"
fi

info "等待配置生效 (10s)..."
sleep 10

# 验证旧 key 失效
HTTP_CODE=$(gateway_code -H "Authorization: Bearer key-phase1-aaa" "$GATEWAY/")
if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
  pass "US-1.3 旧 key 已失效 (HTTP $HTTP_CODE)"
else
  fail "US-1.3 旧 key 仍然有效 (HTTP $HTTP_CODE, 期望 401/403)"
fi

# 验证新 key 生效
HTTP_CODE=$(gateway_code -H "Authorization: Bearer key-phase1-aaa-new" "$GATEWAY/")
if [ "$HTTP_CODE" = "200" ]; then
  pass "US-1.3 新 key 鉴权通过 (HTTP $HTTP_CODE)"
else
  fail "US-1.3 新 key 鉴权失败 (HTTP $HTTP_CODE, 期望 200)"
fi

# ============================================================
section "US-3.3: 禁用路由 key-auth"
# ============================================================
if [ -n "$STRATEGY_ID" ]; then
  RESULT=$(api "/strategyConfig/modifyStrategyConfigStatus" "{\"gwInstanceId\":\"$GW_ID\",\"strategyConfigId\":\"$STRATEGY_ID\",\"status\":0}")
  CODE=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('code',''))")
  if [ "$CODE" = "200" ]; then
    pass "US-3.3 禁用路由 key-auth 成功"
  else
    MSG=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('msg','') or d.get('message',''))")
    fail "US-3.3 禁用失败: $MSG"
  fi

  info "等待配置生效 (10s)..."
  sleep 10

  # 验证禁用后无 key 也能通过
  HTTP_CODE=$(gateway_code "$GATEWAY/")
  if [ "$HTTP_CODE" = "200" ]; then
    pass "US-3.3 禁用后无 key 可通过 (HTTP $HTTP_CODE)"
  else
    fail "US-3.3 禁用后无 key 仍被拒绝 (HTTP $HTTP_CODE, 期望 200)"
  fi
else
  info "US-3.3 跳过 (无 strategyConfigId)"
fi

# ============================================================
section "US-3.4: 重新启用 key-auth"
# ============================================================
if [ -n "$STRATEGY_ID" ]; then
  RESULT=$(api "/strategyConfig/modifyStrategyConfigStatus" "{\"gwInstanceId\":\"$GW_ID\",\"strategyConfigId\":\"$STRATEGY_ID\",\"status\":1}")
  CODE=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('code',''))")
  if [ "$CODE" = "200" ]; then
    pass "US-3.4 重新启用 key-auth 成功"
  else
    MSG=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('msg','') or d.get('message',''))")
    fail "US-3.4 重新启用失败: $MSG"
  fi

  info "等待配置生效 (10s)..."
  sleep 10

  # 验证启用后无 key 被拒绝
  HTTP_CODE=$(gateway_code "$GATEWAY/")
  if [ "$HTTP_CODE" = "401" ]; then
    pass "US-3.4 重新启用后无 key 被拒绝 (HTTP $HTTP_CODE)"
  else
    fail "US-3.4 重新启用后无 key 未被拒绝 (HTTP $HTTP_CODE, 期望 401)"
  fi
else
  info "US-3.4 跳过 (无 strategyConfigId)"
fi

# ============================================================
section "US-2.7: 授权到不存在的路由"
# ============================================================
RESULT=$(api "/applicationauth/createAppAuthByRoute" "{\"gwInstanceId\":\"$GW_ID\",\"appId\":\"$APP_ID_A\",\"grantTargetId\":\"non-existent-route-xyz\",\"authStatus\":1,\"grantType\":\"ROUTER\"}")
CODE=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('code',''))")
if [ "$CODE" != "200" ]; then
  MSG=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('msg','') or d.get('message',''))")
  pass "US-2.7 授权到不存在路由被拒绝: $MSG"
else
  fail "US-2.7 授权到不存在路由未被拒绝 (应返回错误)"
fi

# ============================================================
section "US-1.4: 删除消费者"
# ============================================================
RESULT=$(api "/application/deleteApp" "{\"gwInstanceId\":\"$GW_ID\",\"appId\":\"$APP_ID_B\"}")
CODE=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('code',''))")
if [ "$CODE" = "200" ]; then
  pass "US-1.4 删除消费者 test-consumer-b 成功"
else
  MSG=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('msg','') or d.get('message',''))")
  fail "US-1.4 删除消费者失败: $MSG"
fi

info "等待配置生效 (10s)..."
sleep 10

# 验证删除后 key 失效
HTTP_CODE=$(gateway_code -H "Authorization: Bearer key-phase1-bbb" "$GATEWAY/")
if [ "$HTTP_CODE" = "401" ]; then
  pass "US-1.4 删除后 key 鉴权失败 (HTTP $HTTP_CODE)"
else
  fail "US-1.4 删除后 key 仍有效 (HTTP $HTTP_CODE, 期望 401)"
fi

# ============================================================
section "US-3.5: 删除路由 key-auth 插件"
# ============================================================
if [ -n "$STRATEGY_ID" ]; then
  RESULT=$(api "/strategyConfig/deleteStrategyConfig" "{\"gwInstanceId\":\"$GW_ID\",\"strategyConfigId\":\"$STRATEGY_ID\"}")
  CODE=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('code',''))")
  if [ "$CODE" = "200" ]; then
    pass "US-3.5 删除路由 key-auth 插件成功"
  else
    MSG=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('msg','') or d.get('message',''))")
    fail "US-3.5 删除失败: $MSG"
  fi
else
  info "US-3.5 跳过 (无 strategyConfigId)"
fi

# ============================================================
section "US-3.7: 重复删除 (幂等)"
# ============================================================
if [ -n "$STRATEGY_ID" ]; then
  RESULT=$(api "/strategyConfig/deleteStrategyConfig" "{\"gwInstanceId\":\"$GW_ID\",\"strategyConfigId\":\"$STRATEGY_ID\"}")
  CODE=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('code',''))")
  if [ "$CODE" = "200" ]; then
    pass "US-3.7 重复删除幂等处理成功 (返回 200)"
  else
    MSG=$(echo "$RESULT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('msg','') or d.get('message',''))")
    # 只要不是 500 就算通过
    if [ "$CODE" != "500" ]; then
      pass "US-3.7 重复删除未报 500: code=$CODE, msg=$MSG"
    else
      fail "US-3.7 重复删除报 500: $MSG"
    fi
  fi
else
  info "US-3.7 跳过 (无 strategyConfigId)"
fi

# ============================================================
section "清理: 删除剩余测试数据"
# ============================================================
# 删除 consumer-a
if [ -n "$APP_ID_A" ]; then
  api "/application/deleteApp" "{\"gwInstanceId\":\"$GW_ID\",\"appId\":\"$APP_ID_A\"}" > /dev/null
  info "已删除 test-consumer-a"
fi

# ============================================================
section "测试结果汇总"
# ============================================================
echo ""
if [ "$FAILURES" -eq 0 ]; then
  echo -e "${GREEN}🎉 所有测试通过！${NC}"
else
  echo -e "${RED}⚠️  共 $FAILURES 个测试失败${NC}"
fi
echo ""
echo "测试完成时间: $(date '+%Y-%m-%d %H:%M:%S')"
