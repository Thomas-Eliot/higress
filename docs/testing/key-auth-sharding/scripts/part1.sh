#!/bin/bash
# Phase 1 Part 1: US-1 + US-5 (Consumer 生命周期 + 异步发布)
ADMIN="http://8.137.83.34"
GW_ID="i-lci63hlysglgtpry1sjq"
COOKIE="/tmp/test-cookies.txt"

api() { curl -s -b "$COOKIE" -X POST "${ADMIN}${1}" -H 'Content-Type: application/json' -d "$2"; }

echo "=== 登录 ==="
curl -s -c "$COOKIE" -X POST "$ADMIN/user/login" -H 'Content-Type: application/json' -d '{"account":"admin","password":"Ab123456?"}' > /dev/null

echo ""
echo "=== US-1.1: 创建消费者 ==="
R=$(api "/application/createApp" "{\"gwInstanceId\":\"$GW_ID\",\"appName\":\"test-consumer-a\",\"authType\":5,\"key\":\"key-phase1-aaa\",\"apiKeyLocationType\":\"BEARER\"}")
echo "consumer-a: $R"
R=$(api "/application/createApp" "{\"gwInstanceId\":\"$GW_ID\",\"appName\":\"test-consumer-b\",\"authType\":5,\"key\":\"key-phase1-bbb\",\"apiKeyLocationType\":\"BEARER\"}")
echo "consumer-b: $R"

echo ""
echo "=== 等待异步发布 5s ==="
sleep 5

echo ""
echo "=== US-5.1 + US-1.2: 查询列表验证发布状态 ==="
api "/application/listApps" "{\"gwInstanceId\":\"$GW_ID\",\"current\":1,\"size\":10}" | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(f'total={d[\"data\"][\"total\"]}')
for r in d['data']['records']:
    print(f'  {r[\"appId\"]} | publishStatus={r.get(\"publishStatus\",\"?\")}')
"

echo ""
echo "=== US-1.5: 创建重复 key ==="
R=$(api "/application/createApp" "{\"gwInstanceId\":\"$GW_ID\",\"appName\":\"test-dup\",\"authType\":5,\"key\":\"key-phase1-aaa\",\"apiKeyLocationType\":\"BEARER\"}")
echo "重复key结果: $R"

echo ""
echo "=== 检查 ConfigMap (异步发布后) ==="
kubectl get configmap -n ls-test -l higress.io/biz-type=hi-key-auth-shard --no-headers 2>/dev/null | wc -l
kubectl get wasmplugin key-auth.internal -n ls-test -o jsonpath='{.spec.resourceRefs}' 2>/dev/null | python3 -c "import sys,json;refs=json.load(sys.stdin);print(f'resourceRefs count={len(refs)}')" 2>/dev/null || echo "WasmPlugin CR 不存在或无 resourceRefs"
