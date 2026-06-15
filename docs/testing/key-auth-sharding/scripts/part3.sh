#!/bin/bash
# Phase 1 Part 3: US-1.3 (更新), US-3.3/3.4 (禁用/启用), US-1.4 (删除), US-3.5/3.7 (删除插件/幂等)
ADMIN="http://8.137.83.34"
GATEWAY="http://8.156.87.83"
GW_ID="i-lci63hlysglgtpry1sjq"
COOKIE="/tmp/test-cookies.txt"
STRATEGY_ID="cf9446fdde9fb9d08176076abe269d5c"

api() { curl -s -b "$COOKIE" -X POST "${ADMIN}${1}" -H 'Content-Type: application/json' -d "$2"; }

echo "=== US-1.3: 更新消费者 credential ==="
R=$(api "/application/modifyApp" "{\"gwInstanceId\":\"$GW_ID\",\"appId\":\"test-consumer-a\",\"appName\":\"test-consumer-a\",\"authType\":5,\"key\":\"key-phase1-aaa-new\",\"apiKeyLocationType\":\"BEARER\"}")
echo "更新结果: $R"
echo "等待 10s..."
sleep 10
echo -n "旧key(期望401/403): "
curl -s --connect-timeout 5 --max-time 8 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer key-phase1-aaa' "$GATEWAY/"
echo ""
echo -n "新key(期望200): "
curl -s --connect-timeout 5 --max-time 8 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer key-phase1-aaa-new' "$GATEWAY/"
echo ""

echo ""
echo "=== US-3.3: 禁用路由 key-auth ==="
R=$(api "/strategyConfig/modifyStrategyConfigStatus" "{\"gwInstanceId\":\"$GW_ID\",\"strategyConfigId\":\"$STRATEGY_ID\",\"status\":0}")
echo "禁用结果: $R"
echo "等待 10s..."
sleep 10
echo -n "禁用后无key(期望200): "
curl -s --connect-timeout 5 --max-time 8 -o /dev/null -w '%{http_code}' "$GATEWAY/"
echo ""

echo ""
echo "=== US-3.4: 重新启用 key-auth ==="
R=$(api "/strategyConfig/modifyStrategyConfigStatus" "{\"gwInstanceId\":\"$GW_ID\",\"strategyConfigId\":\"$STRATEGY_ID\",\"status\":1}")
echo "启用结果: $R"
echo "等待 10s..."
sleep 10
echo -n "启用后无key(期望401): "
curl -s --connect-timeout 5 --max-time 8 -o /dev/null -w '%{http_code}' "$GATEWAY/"
echo ""

echo ""
echo "=== US-1.4: 删除消费者 test-consumer-b ==="
R=$(api "/application/deleteApp" "{\"gwInstanceId\":\"$GW_ID\",\"appId\":\"test-consumer-b\"}")
echo "删除结果: $R"
echo "等待 10s..."
sleep 10
echo -n "删除后bbb-key(期望401): "
curl -s --connect-timeout 5 --max-time 8 -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer key-phase1-bbb' "$GATEWAY/"
echo ""

echo ""
echo "=== US-3.5: 删除路由 key-auth 插件 ==="
R=$(api "/strategyConfig/deleteStrategyConfig" "{\"gwInstanceId\":\"$GW_ID\",\"strategyConfigId\":\"$STRATEGY_ID\"}")
echo "删除插件结果: $R"

echo ""
echo "=== US-3.7: 重复删除(幂等) ==="
R=$(api "/strategyConfig/deleteStrategyConfig" "{\"gwInstanceId\":\"$GW_ID\",\"strategyConfigId\":\"$STRATEGY_ID\"}")
echo "重复删除结果: $R"

echo ""
echo "=== 清理: 删除 consumer-a ==="
api "/application/deleteApp" "{\"gwInstanceId\":\"$GW_ID\",\"appId\":\"test-consumer-a\"}"
echo ""
echo "=== Part 3 完成 ==="
