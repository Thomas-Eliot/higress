#!/bin/bash
set -ex

# 在 amd64 构建机执行：把 build-envoy.sh 产出的 envoy 二进制打进 gateway 镜像并推送。
#
# Usage:
#   sh build-gateway-image.sh [TAG]
#   例: sh build-gateway-image.sh quota-rule-enforcefix-20260618
#
# ⚠️ 两条踩过的坑（务必照做）：
#   1) 用「新 TAG」别复用旧 tag（如 :quota-rule）：线上 gateway 容器 imagePullPolicy=IfNotPresent，
#      同 tag 换内容节点不会重拉。默认 TAG 已带日期，每次构建请给不同 TAG。
#   2) docker build 必须 --no-cache：envoy 二进制 mtime 固定(Jan-1-2000)+同 size 时，
#      COPY 层会「假命中」缓存导致打进旧二进制（详见 quota-gateway-build-cache-blocker）。

TAG="${1:-quota-enforce-develop-$(date +%Y%m%d)}"   # develop 线 + decodeData 修复（feat/quota-enforce-fix）
REGISTRY="registry.cn-shanghai.aliyuncs.com/daofeng/gateway"
BASE_IMAGE="${BASE_IMAGE:-registry.cn-shanghai.aliyuncs.com/daofeng/gateway:2.1.12}"   # 含 envoy 以外全部内容的基底
WORKDIR="/workspace/gateway-image"
OUT_DIR="/workspace/proxy/out"

# 只取一个 tarball，避免选错（多个时取最新 mtime）。
TARBALLS=($(ls ${OUT_DIR}/envoy-*.tar.gz 2>/dev/null))
if [ ${#TARBALLS[@]} -eq 0 ]; then
  echo "ERROR: ${OUT_DIR}/ 下没有 envoy-*.tar.gz —— 先跑 sh build-envoy.sh"
  exit 1
elif [ ${#TARBALLS[@]} -gt 1 ]; then
  echo "WARNING: 发现多个 tarball，将用 mtime 最新的一个："
  ls -la ${OUT_DIR}/envoy-*.tar.gz
fi
TARBALL=$(ls -t ${OUT_DIR}/envoy-*.tar.gz | head -1)
echo "Using tarball: ${TARBALL} ($(du -h "${TARBALL}" | cut -f1))"

rm -rf "${WORKDIR}"
mkdir -p "${WORKDIR}/amd64"
tar xzf "${TARBALL}" -C "${WORKDIR}/amd64/"

# 验证 envoy 二进制存在且可执行。
ENVOY_BIN="${WORKDIR}/amd64/usr/local/bin/envoy"
if [ ! -f "${ENVOY_BIN}" ]; then
  echo "ERROR: tarball 内未找到 ${ENVOY_BIN}；tarball 内容："
  tar tzf "${TARBALL}"
  exit 1
fi
echo "Envoy binary size: $(du -h "${ENVOY_BIN}" | cut -f1)"

cat > "${WORKDIR}/Dockerfile" <<EOF
FROM ${BASE_IMAGE}
COPY amd64/usr/local/bin/envoy /usr/local/bin/envoy
EOF

# --no-cache + --platform amd64：见上文坑 2；目标节点单架构 amd64，无需 manifest。
docker build --no-cache --platform linux/amd64 -t "${REGISTRY}:${TAG}" "${WORKDIR}"
docker push "${REGISTRY}:${TAG}"

echo "=== GATEWAY IMAGE PUSHED ==="
echo ">>> 镜像: ${REGISTRY}:${TAG}"
echo ">>> digest: $(docker inspect --format='{{index .RepoDigests 0}}' "${REGISTRY}:${TAG}" 2>/dev/null || echo '（取不到，docker images --digests 查）')"
echo ">>> 部署: kubectl -n ls-test set image deploy/higress-gateway higress-gateway=${REGISTRY}:${TAG} && kubectl -n ls-test rollout restart deploy/higress-gateway"
echo ">>> 验证: 从 gateway 容器内对 perf-17759「带 body」压测 /v1/chat/completions，超额应 429（degraded_sync_denied 增长）"
