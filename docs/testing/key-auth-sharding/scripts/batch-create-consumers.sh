#!/bin/bash
# Phase 2 压测脚本：批量创建 40000 个 consumer
# 分批执行，每批 1000 个，并发 10 个请求，批间间隔 5s

set -e

BASE_URL="http://8.137.83.34:80/application/createApp"
GW_INSTANCE_ID="i-lci63hlysglgtpry1sjq"
TOTAL=40000
BATCH_SIZE=1000
CONCURRENCY=10
BATCH_INTERVAL=5

# 登录获取 cookie
echo "[$(date '+%H:%M:%S')] Logging in..."
LOGIN_RESPONSE=$(curl -s -D - 'http://8.137.83.34:80/user/login' \
  -H 'Content-Type: application/json' \
  -d '{"account":"admin","password":"Ab123456?"}' 2>&1)

COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i 'Set-Cookie:' | grep -o 'csb-sessionId-GATEWAY=[^;]*')
if [ -z "$COOKIE" ]; then
  echo "ERROR: Failed to login"
  echo "$LOGIN_RESPONSE"
  exit 1
fi
echo "[$(date '+%H:%M:%S')] Login success: $COOKIE"

# 统计
SUCCESS=0
FAIL=0
START_TIME=$(date +%s)

# 结果目录
RESULT_DIR="/tmp/phase2-results"
mkdir -p "$RESULT_DIR"

create_consumer() {
  local idx=$1
  local name="perf-consumer-$(printf '%05d' $idx)"
  local key="perf-key-$(printf '%05d' $idx)"
  
  local response=$(curl -s -w "\n%{http_code}" -H "Cookie: $COOKIE" \
    -H 'Content-Type: application/json' \
    "$BASE_URL" \
    -d "{\"gwInstanceId\":\"$GW_INSTANCE_ID\",\"appName\":\"$name\",\"key\":\"$key\",\"authType\":3,\"apiKeyLocationType\":\"BEARER\"}" \
    --connect-timeout 10 --max-time 30)
  
  local http_code=$(echo "$response" | tail -1)
  local body=$(echo "$response" | sed '$d')
  
  if echo "$body" | grep -q '"code":200'; then
    echo "OK" > "$RESULT_DIR/$idx.result"
  else
    echo "FAIL: $http_code $body" > "$RESULT_DIR/$idx.result"
  fi
}

echo "[$(date '+%H:%M:%S')] Starting batch creation: total=$TOTAL, batch=$BATCH_SIZE, concurrency=$CONCURRENCY"
echo ""

BATCH_NUM=0
for ((i=1; i<=TOTAL; i++)); do
  create_consumer $i &
  
  # 控制并发数
  if (( i % CONCURRENCY == 0 )); then
    wait
  fi
  
  # 每批结束时统计并暂停
  if (( i % BATCH_SIZE == 0 )); then
    wait
    BATCH_NUM=$((BATCH_NUM + 1))
    
    # 统计本批结果
    BATCH_SUCCESS=$(grep -l "^OK$" "$RESULT_DIR"/*.result 2>/dev/null | wc -l)
    BATCH_FAIL=$(grep -L "^OK$" "$RESULT_DIR"/*.result 2>/dev/null | wc -l)
    
    ELAPSED=$(( $(date +%s) - START_TIME ))
    echo "[$(date '+%H:%M:%S')] Batch $BATCH_NUM done: created=$i/$TOTAL, elapsed=${ELAPSED}s, rate=$(echo "scale=1; $i/$ELAPSED" | bc 2>/dev/null || echo "N/A")/s"
    
    # 检查最近的 publishStatus
    PUB_CHECK=$(curl -s -H "Cookie: $COOKIE" -H 'Content-Type: application/json' \
      'http://8.137.83.34:80/application/listApps' \
      -d "{\"gwInstanceId\":\"$GW_INSTANCE_ID\",\"pageNum\":1,\"pageSize\":3}" 2>/dev/null | \
      python3 -c "import sys,json; d=json.load(sys.stdin); records=d.get('data',{}).get('records',[]); print(f'total={d[\"data\"][\"total\"]}, latest_status={records[0][\"publishStatus\"] if records else \"N/A\"}')" 2>/dev/null || echo "check failed")
    echo "         Status: $PUB_CHECK"
    
    if (( i < TOTAL )); then
      echo "         Sleeping ${BATCH_INTERVAL}s before next batch..."
      sleep $BATCH_INTERVAL
    fi
  fi
done

# 等待所有后台任务完成
wait

# 最终统计
TOTAL_SUCCESS=$(grep -rl "^OK$" "$RESULT_DIR"/ 2>/dev/null | wc -l)
TOTAL_FAIL=$((TOTAL - TOTAL_SUCCESS))
END_TIME=$(date +%s)
TOTAL_ELAPSED=$((END_TIME - START_TIME))

echo ""
echo "=========================================="
echo "Phase 2 Batch Creation Complete"
echo "=========================================="
echo "Total: $TOTAL"
echo "Success: $TOTAL_SUCCESS"
echo "Failed: $TOTAL_FAIL"
echo "Elapsed: ${TOTAL_ELAPSED}s"
echo "Rate: $(echo "scale=1; $TOTAL/$TOTAL_ELAPSED" | bc 2>/dev/null || echo "N/A") consumers/s"
echo "=========================================="

# 清理
rm -rf "$RESULT_DIR"
