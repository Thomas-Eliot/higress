#!/bin/bash
# 小批量测试：创建 10 个 consumer 验证脚本逻辑

BASE_URL="http://8.137.83.34:80/application/createApp"
GW_INSTANCE_ID="i-lci63hlysglgtpry1sjq"

# 登录
LOGIN_RESPONSE=$(curl -s -D - 'http://8.137.83.34:80/user/login' \
  -H 'Content-Type: application/json' \
  -d '{"account":"admin","password":"Ab123456?"}' 2>&1)

COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i 'Set-Cookie:' | grep -o 'csb-sessionId-GATEWAY=[^;]*')
if [ -z "$COOKIE" ]; then
  echo "ERROR: Failed to login"
  exit 1
fi
echo "Login OK: $COOKIE"

SUCCESS=0
FAIL=0
START_TIME=$(date +%s)

for i in $(seq 1 10); do
  name="perf-consumer-$(printf '%05d' $i)"
  key="perf-key-$(printf '%05d' $i)"
  
  response=$(curl -s -H "Cookie: $COOKIE" \
    -H 'Content-Type: application/json' \
    "$BASE_URL" \
    -d "{\"gwInstanceId\":\"$GW_INSTANCE_ID\",\"appName\":\"$name\",\"key\":\"$key\",\"authType\":3,\"apiKeyLocationType\":\"BEARER\"}" \
    --connect-timeout 10 --max-time 30)
  
  if echo "$response" | grep -q '"code":200'; then
    SUCCESS=$((SUCCESS + 1))
  else
    FAIL=$((FAIL + 1))
    echo "FAIL [$i]: $response"
  fi
done

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
echo ""
echo "Done: success=$SUCCESS, fail=$FAIL, elapsed=${ELAPSED}s"
