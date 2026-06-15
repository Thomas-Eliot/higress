#!/bin/bash
# Phase 2 压测 v2：使用 GNU parallel / xargs 并发
# 批量创建 40000 个 consumer

BASE_URL="http://8.137.83.34:80/application/createApp"
GW_INSTANCE_ID="i-lci63hlysglgtpry1sjq"
TOTAL=40000
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

echo "[$(date '+%H:%M:%S')] Login OK" | tee "$LOG"
echo "[$(date '+%H:%M:%S')] Creating $TOTAL consumers, concurrency=$CONCURRENCY" | tee -a "$LOG"

START_TIME=$(date +%s)

# 生成序列并用 xargs 并发执行
seq 11 $TOTAL | xargs -P $CONCURRENCY -I {} bash -c '
  idx={}
  name="perf-consumer-$(printf "%05d" $idx)"
  key="perf-key-$(printf "%05d" $idx)"
  resp=$(curl -s -H "Cookie: '"$COOKIE"'" \
    -H "Content-Type: application/json" \
    "'"$BASE_URL"'" \
    -d "{\"gwInstanceId\":\"'"$GW_INSTANCE_ID"'\",\"appName\":\"$name\",\"key\":\"$key\",\"authType\":3,\"apiKeyLocationType\":\"BEARER\"}" \
    --connect-timeout 10 --max-time 30 2>/dev/null)
  if echo "$resp" | grep -q "\"code\":200"; then
    echo "S"
  else
    echo "F:$idx:$resp" >&2
  fi
' 2>/tmp/phase2-errors.log | \
  awk 'BEGIN{s=0; t=systime()} {s++; if(s%1000==0) {elapsed=systime()-t; printf "[%s] Progress: %d/%d (%.1f/s)\n", strftime("%H:%M:%S"), s, '"$TOTAL"', s/elapsed}}' | \
  tee -a "$LOG"

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
ERRORS=$(wc -l < /tmp/phase2-errors.log 2>/dev/null | tr -d ' ')

echo "" | tee -a "$LOG"
echo "==========================================" | tee -a "$LOG"
echo "Phase 2 Complete" | tee -a "$LOG"
echo "Elapsed: ${ELAPSED}s" | tee -a "$LOG"
echo "Errors: $ERRORS" | tee -a "$LOG"
echo "Rate: $(echo "scale=1; ($TOTAL-10)/$ELAPSED" | bc 2>/dev/null || echo '?') consumers/s" | tee -a "$LOG"
echo "==========================================" | tee -a "$LOG"

if [ "$ERRORS" -gt 0 ]; then
  echo "Sample errors:" | tee -a "$LOG"
  head -5 /tmp/phase2-errors.log | tee -a "$LOG"
fi
