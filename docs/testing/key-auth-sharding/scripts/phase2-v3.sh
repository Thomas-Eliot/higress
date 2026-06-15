#!/bin/bash
# Phase 2 压测 v3：简单循环 + 后台并发
# 每批 500 个，并发 20，批间等待所有完成

BASE_URL="http://8.137.83.34:80/application/createApp"
GW_INSTANCE_ID="i-lci63hlysglgtpry1sjq"
START_IDX=11
END_IDX=40000
CONCURRENCY=20
LOG="/tmp/phase2-progress.log"

# 登录
COOKIE=$(curl -s -D - 'http://8.137.83.34:80/user/login' \
  -H 'Content-Type: application/json' \
  -d '{"account":"admin","password":"Ab123456?"}' 2>&1 | \
  grep -i 'Set-Cookie:' | grep -o 'csb-sessionId-GATEWAY=[^;]*')

if [ -z "$COOKIE" ]; then
  echo "ERROR: Login failed" | tee "$LOG"
  exit 1
fi

echo "[$(date '+%H:%M:%S')] Login OK: $COOKIE" > "$LOG"
echo "[$(date '+%H:%M:%S')] Range: $START_IDX to $END_IDX, concurrency=$CONCURRENCY" >> "$LOG"

START_SEC=$(date +%s)
SUCCESS=0
FAIL=0
RUNNING=0

for ((i=START_IDX; i<=END_IDX; i++)); do
  name="perf-consumer-$(printf '%05d' $i)"
  key="perf-key-$(printf '%05d' $i)"
  
  (
    resp=$(curl -s -H "Cookie: $COOKIE" \
      -H 'Content-Type: application/json' \
      "$BASE_URL" \
      -d "{\"gwInstanceId\":\"$GW_INSTANCE_ID\",\"appName\":\"$name\",\"key\":\"$key\",\"authType\":3,\"apiKeyLocationType\":\"BEARER\"}" \
      --connect-timeout 10 --max-time 30 2>/dev/null)
    if echo "$resp" | grep -q '"code":200'; then
      exit 0
    else
      echo "$i:$resp" >> /tmp/phase2-errors.log
      exit 1
    fi
  ) &
  
  RUNNING=$((RUNNING + 1))
  
  if (( RUNNING >= CONCURRENCY )); then
    wait
    RUNNING=0
  fi
  
  # 每 1000 个打印进度
  DONE=$((i - START_IDX + 1))
  if (( DONE % 1000 == 0 )); then
    ELAPSED=$(( $(date +%s) - START_SEC ))
    if [ "$ELAPSED" -gt 0 ]; then
      RATE=$(( DONE / ELAPSED ))
    else
      RATE="?"
    fi
    echo "[$(date '+%H:%M:%S')] Progress: $DONE/$((END_IDX - START_IDX + 1)) (${RATE}/s, ${ELAPSED}s)" >> "$LOG"
    echo "[$(date '+%H:%M:%S')] Progress: $DONE/$((END_IDX - START_IDX + 1)) (${RATE}/s, ${ELAPSED}s)"
  fi
done

wait

END_SEC=$(date +%s)
TOTAL_ELAPSED=$((END_SEC - START_SEC))
TOTAL_DONE=$((END_IDX - START_IDX + 1))
ERRORS=$(wc -l < /tmp/phase2-errors.log 2>/dev/null | tr -d ' ')
[ -z "$ERRORS" ] && ERRORS=0

echo "" >> "$LOG"
echo "==========================================" >> "$LOG"
echo "Phase 2 Complete" >> "$LOG"
echo "Total: $TOTAL_DONE" >> "$LOG"
echo "Errors: $ERRORS" >> "$LOG"
echo "Elapsed: ${TOTAL_ELAPSED}s" >> "$LOG"
if [ "$TOTAL_ELAPSED" -gt 0 ]; then
  echo "Rate: $((TOTAL_DONE / TOTAL_ELAPSED)) consumers/s" >> "$LOG"
fi
echo "==========================================" >> "$LOG"

cat "$LOG"

if [ "$ERRORS" -gt 0 ]; then
  echo ""
  echo "Sample errors (first 5):"
  head -5 /tmp/phase2-errors.log
fi
