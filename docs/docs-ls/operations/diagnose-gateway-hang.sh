#!/usr/bin/env bash
# diagnose-gateway-hang.sh
# 用途：当 higress-gateway 启动后卡死、Envoy admin :15000 不响应、日志停止时，
#       直接抓 Envoy 进程的线程状态 / 内核栈 / 挂起的 socket，定位主线程卡在哪。
# 用法：./diagnose-gateway-hang.sh [POD] [NS]
#   默认 POD=higress-gateway-c497d6b-cxmx7  NS=higress-system
set -u
POD="${1:-higress-gateway-c497d6b-cxmx7}"
NS="${2:-higress-system}"
C=higress-gateway
KE="kubectl --request-timeout=20s exec -n $NS $POD -c $C --"

echo "############ 0. admin/status 端口探活（全部带 3s 超时） ############"
$KE sh -c '
for p in 15000:/server_info 15000:/ready 15020:/healthz/ready 15021:/healthz/ready; do
  port=${p%%:*}; path=${p#*:}
  code=$(curl -s --max-time 3 -o /dev/null -w "%{http_code}" "localhost:$port$path")
  echo "  $port$path -> $code"
done'

echo "############ 1. envoy 进程 + 所有线程状态 ############"
$KE sh -c '
PID=$(pidof envoy 2>/dev/null); [ -z "$PID" ] && PID=$(ps -eo pid,comm 2>/dev/null | awk "/envoy/{print \$1; exit}")
echo "  envoy_pid=$PID"
echo "  --- 线程名(comm) + 状态(R=跑 S=睡 D=不可中断睡眠) + wchan(内核函数) ---"
for t in /proc/$PID/task/*; do
  tid=${t##*/}
  name=$(cat "$t/comm" 2>/dev/null)
  st=$(awk "/^State:/{print \$2}" "$t/status" 2>/dev/null)
  wc=$(cat "$t/wchan" 2>/dev/null)
  printf "    tid=%-7s state=%-2s wchan=%-24s %s\n" "$tid" "$st" "$wc" "$name"
done
echo "  --- 主线程(tid=$PID) 内核栈 ---"
cat /proc/$PID/task/$PID/stack 2>/dev/null || echo "    (stack 不可读，需 root/ptrace)"
echo "  --- 主线程 当前 syscall ---"
cat /proc/$PID/task/$PID/syscall 2>/dev/null || echo "    (syscall 不可读)"
'

echo "############ 2. socket：是否有挂起的 connect(SYN_SENT) / admin 是否在监听 ############"
$KE sh -c '
if command -v ss >/dev/null 2>&1; then T="ss -tan"; L="ss -ltn";
elif command -v netstat >/dev/null 2>&1; then T="netstat -tan"; L="netstat -ltn";
else T=""; fi
if [ -n "$T" ]; then
  echo "  --- 监听 15000/15020/15021 ---"; $L 2>/dev/null | grep -E ":1500[0-9]|:1502[0-1]" || echo "    (admin/status 端口未监听!)"
  echo "  --- 非 ESTABLISHED 的出方向连接(SYN_SENT = connect 卡住) ---"; $T 2>/dev/null | grep -iE "SYN[_-]SENT" | head -20 || echo "    (无)"
else
  echo "  ss/netstat 缺失，看 /proc/net/tcp 状态统计 (02=SYN_SENT 0A=LISTEN 01=ESTAB):"
  awk "NR>1{print \$4}" /proc/net/tcp 2>/dev/null | sort | uniq -c
fi
'
echo "############ done ############"
