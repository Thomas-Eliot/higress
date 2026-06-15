#!/bin/bash
# Phase 2 压测执行脚本
# 批量创建 40000 个 consumer，并发 10，每批 1000，批间隔 3s
# 预计耗时：40000 / (10并发 * ~5/s) ≈ 800s + 间隔 ≈ 15-20 分钟

BASE_URL="http://8.137.83.34:80/application/createApp"
GW_INSTANCE_ID="i-lci63hlysglgtpry1sjq"
TOTAL=40000
BATCH_SIZE=1000
CONCURRENCY=10
BATCH_INTERVAL=3
LOG_FILE="/tmp/phase2-progress.log"

# 登录
LOGIN_RESPONSE=$(curl -s -D - 'http://8.137.83.34:80/user/login' \
  -H 'Content-Type: application/json' \
  -d '{"account":"admin","password":"Ab123456?"}' 2>&1)

COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i 'Set-Cookie:' | grep -o 'csb-sessionId-GATEWAY=[^;]*')
if [ -z "$COOKIE" ]; then
  echo "ERROR: Failed to login" | tee "$LOG_FILE"
  exit 1
fi
echo "[$(date '+%H:%M:%S')] Login OK" | tee "$LOG_FILE"
echo "[$(date '+%H:%M:%S')] Starting: total=$TOTAL, batch=$BATCH_SIZE, concurrency=$CONCURRENCY" | tee -a "$LOG_FILE"

SUCCESS=0
FAIL=0
START_TIME=$(date +%s)
RESULT_DIR="/tmp/phase2-results"
rm -rf "$RESULT_DIR"
mkdir -p "$RESULT_DIR"

create_consumer() {
  local idx=$1
  local name="perf-consumer-$(printf '%05d' $idx)"
  local key="perf-key-$(printf '%05d' $idx)"
  
  local response=$(curl -s -H "Cookie: $COOKIE" \
    -H 'Content-Type: application/json' \
    "$BASE_URL" \
    -d "{\"gwInstanceId\":\"$GW_INSTANCE_ID\",\"appName\":\"$name\",\"key\":\"$key\",\"authType\":3,\"apiKeyLocationType\":\"BEARER\"}" \
    --connect-timeout 10 --max-time 30 2>/dev/null)
  
  if echo "$response" | grep -q '"code":200'; then
    echo "OK" > "$RESULT_DIR/$idx.result"
  else
    echo "FAIL: $response" > "$RESULT_DIR/$idx.result"
  fi
}

# 从 11 开始（前 10 个已在测试中创建）
START_IDX=11
END_IDX=$TOTAL

RUNNING=0
BATCH_NUM=0

for ((i=START_IDX; i<=END_IDX; i++)); do
  create_consumer $i &
  RUNNING=$((RUNNING + 1))
  
  # 控制并发数
  if (( RUNNING >= CONCURRENCY )); then
    wait -n 2>/dev/null || wait
    RUNNING=$((RUNNING - 1))
  fi
  
  # 每批结束时统计
  if (( (i - START_IDX + 1) % BATCH_SIZE == 0 )); then
    wait
    RUNNING=0
    BATCH_NUM=$((BATCH_NUM + 1))
    
    CREATED=$((i - START_IDX + 1))
    ELAPSED=$(( $(date +%s) - START_TIME ))
    RATE=$(echo "scale=1; $CREATED/$ELAPSED" | bc 2>/dev/null || echo "?")
    
    echo "[$(date '+%H:%M:%S')] Batch $BATCH_NUM: created=$CREATED/$((END_IDX-START_IDX+1)), elapsed=${ELAPSED}s, rate=${RATE}/s" | tee -a "$LOG_FILE"
    
    if (( i < END_IDX )); then
      sleep $BATCH_INTERVAL
    fi
  fi
done

wait

# 最终统计
TOTAL_CREATED=$((END_IDX - START_IDX + 1))
TOTAL_SUCCESS=$(grep -rl "^OK$" "$RESULT_DIR"/ 2>/dev/null | wc -l | tr -d ' ')
TOTAL_FAIL=$((TOTAL_CREATED - TOTAL_SUCCESS))
END_TIME=$(date +%s)
TOTAL_ELAPSED=$((END_TIME - START_TIME))
RATE=$(echo "scale=1; $TOTAL_CREATED/$TOTAL_ELAPSED" | bc 2>/dev/null || echo "?")

echo "" | tee -a "$LOG_FILE"
echo "==========================================" | tee -a "$LOG_FILE"
echo "Phase 2 Complete" | tee -a "$LOG_FILE"
echo "==========================================" | tee -a "$LOG_FILE"
echo "Total created: $TOTAL_CREATED" | tee -a "$LOG_FILE"
echo "Success: $TOTAL_SUCCESS" | tee -a "$LOG_FILE"
echo "Failed: $TOTAL_FAIL" | tee -a "$LOG_FILE"
echo "Elapsed: ${TOTAL_ELAPSED}s" | tee -a "$LOG_FILE"
echo "Rate: ${RATE} consumers/s" | tee -a "$LOG_FILE"
echo "==========================================" | tee -a "$LOG_FILE"

# 打印失败样本
if [ "$TOTAL_FAIL" -gt 0 ]; then
  echo "" | tee -a "$LOG_FILE"
  echo "Sample failures:" | tee -a "$LOG_FILE"
  grep -l -v "^OK$" "$RESULT_DIR"/*.result 2>/dev/null | head -5 | while read f; do
    echo "  $(basename $f): $(cat $f)" | tee -a "$LOG_FILE"
  done
fi

rm -rf "$RESULT_DIR"
echo "" | tee -a "$LOG_FILE"
echo "Done. Log: $LOG_FILE" | tee -a "$LOG_FILE"
