#!/bin/bash
# Phase 1 Part 2: US-3 (路由插件开关) + US-2 (授权) + US-4 (全量发布) + 数据面验证
ADMIN="http://8.137.83.34"
GATEWAY="http://8.156.87.83"
GW_ID="i-lci63hlysglgtpry1sjq"
COOKIE="/tmp/test-cookies.txt"
ROUTE_ID="ls-test-echo"

api() { curl -s -b "$COOKIE" -X POST "${ADMIN}${1}" -H 'Content-Type: application/json' -d "$2"; }

echo "=== US-3.1: 为路由启用 key-auth 插件 ==="
R=$(api "/strategyConfig/createStrategyConfig" "{\"gwInstanceId\":\"$GW_ID\",\"strategyName\":\"key-auth\",\"routeIds\":[\"$ROUTE_ID\"],\"config\":{}}")
echo "$R"
STRATEGY_ID=$(echo "$R" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('data',''))" 2>/dev/null)
echo "strategyConfigId=$STRATEGY_ID"

echo ""
echo "=== US-3.2: 查询路由插件列表 ==="
R=$(api "/route/listRoutePlugins" "{\"gwInstanceId\":\"$GW_ID\",\"routeId\":\"$ROUTE_ID\"}")
echo "$R" | python3 -c "
import sys,json
d=json.load(sys.stdin)
if d.get('code')==200:
    plugins=d.get('data',[])
    print(f'路由插件数量: {len(plugins)}')
    for p in plugins:
        print(f'  name={p.get(\"strategyName\",\"?\")} status={p.get(\"status\",\"?\")} id={p.get(\"strategyConfigId\",\"?\")}')
else:
    print(f'ERROR: {d}')
"

echo ""
echo "=== US-2.1: 授权 consumer-a 到路由 ==="
R=$(api "/applicationauth/createAppAuthByRoute" "{\"gwInstanceId\":\"$GW_ID\",\"appId\":\"test-consumer-a\",\"grantTargetId\":\"$ROUTE_ID\",\"authStatus\":1,\"grantType\":\"ROUTER\"}")
echo "授权结果: $R"

echo ""
echo "=== US-4.1: 全量发布 ==="
R=$(api "/application/fullPublish" "{\"gwInstanceId\":\"$GW_ID\"}")
echo "全量发布: $R"

echo ""
echo "=== 等待 Controller 推送 (15s) ==="
sleep 15

echo ""
echo "=== US-6: 验证分片数据 ==="
echo "--- 分片 ConfigMap ---"
kubectl get configmap -n ls-test -l higress.io/biz-type=hi-key-auth-shard -o name 2>/dev/null
echo ""
echo "--- route-switches ---"
kubectl get configmap hi-key-auth-route-switches -n ls-test -o jsonpath='{.data.matchRules}' 2>/dev/null || echo "(不存在)"
echo ""
echo "--- WasmPlugin CR ---"
kubectl get wasmplugin key-auth.internal -n ls-test -o jsonpath='{.spec.resourceRefs[*].configMapName}' 2>/dev/null || echo "(不存在)"
echo ""

echo ""
echo "=== US-2.4: 已授权 key 鉴权 (期望 200) ==="
HTTP=$(curl -s --connect-timeout 5 --max-time 8 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer key-phase1-aaa" "$GATEWAY/")
echo "HTTP $HTTP"

echo ""
echo "=== US-2.5: 未授权 key 鉴权 (期望 403) ==="
HTTP=$(curl -s --connect-timeout 5 --max-time 8 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer key-phase1-bbb" "$GATEWAY/")
echo "HTTP $HTTP"

echo ""
echo "=== US-2.6: 无 key (期望 401) ==="
HTTP=$(curl -s --connect-timeout 5 --max-time 8 -o /dev/null -w '%{http_code}' "$GATEWAY/")
echo "HTTP $HTTP"

echo ""
echo "=== US-2.7: 授权到不存在的路由 ==="
R=$(api "/applicationauth/createAppAuthByRoute" "{\"gwInstanceId\":\"$GW_ID\",\"appId\":\"test-consumer-a\",\"grantTargetId\":\"non-existent-route\",\"authStatus\":1,\"grantType\":\"ROUTER\"}")
echo "结果: $R"
