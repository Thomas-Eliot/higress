#!/bin/bash
# 向 key-auth.internal WasmPlugin 的 defaultConfig.consumers 中批量添加 consumer
# 无需 jq，仅依赖 kubectl + python3（或 python）
#
# 用法: ./patch-key-auth-consumers.sh -n <namespace> -c <consumer_count> [--start <start_index>]
#
# 示例:
#   ./patch-key-auth-consumers.sh -n ls-test -c 100
#   ./patch-key-auth-consumers.sh -n ls-test -c 1000 --start 200

set -euo pipefail

NAMESPACE=""
COUNT=0
START=0
RESOURCE_NAME="key-auth.internal"

# 检测可用的 python
PYTHON=""
if command -v python3 &>/dev/null; then
  PYTHON=python3
elif command -v python &>/dev/null; then
  PYTHON=python
else
  echo "错误: 需要 python3 或 python"
  exit 1
fi

usage() {
  echo "用法: $0 -n <namespace> -c <consumer_count> [--start <start_index>]"
  echo ""
  echo "参数:"
  echo "  -n, --namespace   WasmPlugin 所在的 namespace"
  echo "  -c, --count       要添加的 consumer 数量"
  echo "  --start           consumer 编号起始值 (默认: 0)"
  echo ""
  echo "示例:"
  echo "  $0 -n ls-test -c 1000"
  echo "  $0 -n ls-test -c 5000 --start 1000"
  exit 1
}

# 解析参数
while [[ $# -gt 0 ]]; do
  case $1 in
    -n|--namespace)
      NAMESPACE="$2"
      shift 2
      ;;
    -c|--count)
      COUNT="$2"
      shift 2
      ;;
    --start)
      START="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      echo "未知参数: $1"
      usage
      ;;
  esac
done

if [[ -z "$NAMESPACE" || "$COUNT" -le 0 ]]; then
  echo "错误: namespace 和 count 为必填参数，且 count 必须大于 0"
  usage
fi

echo "=== 向 ${NAMESPACE}/${RESOURCE_NAME} 添加 ${COUNT} 个 consumer (起始编号: ${START}) ==="

# 获取当前 WasmPlugin JSON
echo "正在获取当前 WasmPlugin 配置..."
TMPFILE=$(mktemp /tmp/wasmplugin-XXXXXX.json)
OUTFILE=$(mktemp /tmp/wasmplugin-out-XXXXXX.json)
trap "rm -f ${TMPFILE} ${OUTFILE}" EXIT

kubectl get wasmplugin "${RESOURCE_NAME}" -n "${NAMESPACE}" -o json > "${TMPFILE}"

# 用 python 合并 consumers 并输出完整资源
${PYTHON} - "${TMPFILE}" "${OUTFILE}" "${COUNT}" "${START}" <<'PYEOF'
import json, sys, string, random, time

input_file = sys.argv[1]
output_file = sys.argv[2]
count = int(sys.argv[3])
start = int(sys.argv[4])

with open(input_file, 'r') as f:
    resource = json.load(f)

existing = resource.get('spec', {}).get('defaultConfig', {}).get('consumers', [])
print(f"当前 consumer 数量: {len(existing)}")

# 生成新 consumers
chars = string.ascii_letters + string.digits
new_consumers = []
for i in range(start, start + count):
    credential = ''.join(random.choices(chars, k=32))
    padded = f"{i:05d}"
    org_index = i % 100
    new_consumers.append({
        "credential": f"Bearer {credential}",
        "description": f"Org: org-{org_index}, ApiKey: consumer-{padded}",
        "in_header": True,
        "in_query": False,
        "keys": ["Authorization"],
        "name": f"consumer-{padded}"
    })

# 合并
resource['spec']['defaultConfig']['consumers'] = existing + new_consumers

# 清理 managedFields 和 last-applied-configuration 避免体积超限
resource.get('metadata', {}).pop('managedFields', None)
resource.get('metadata', {}).get('annotations', {}).pop('kubectl.kubernetes.io/last-applied-configuration', None)

print(f"合并后 consumer 数量: {len(resource['spec']['defaultConfig']['consumers'])}")

with open(output_file, 'w') as f:
    json.dump(resource, f)
PYEOF

# 写回集群（用 replace 避免 last-applied-configuration annotation 体积超限）
echo "正在写入 WasmPlugin..."
kubectl replace -f "${OUTFILE}"

# 验证
TOTAL=$(kubectl get wasmplugin "${RESOURCE_NAME}" -n "${NAMESPACE}" -o jsonpath='{.spec.defaultConfig.consumers}' | ${PYTHON} -c "import sys,json; print(len(json.loads(sys.stdin.read())))")

echo ""
echo "=== 完成 ==="
echo "当前 consumer 总数: ${TOTAL}"
