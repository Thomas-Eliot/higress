#!/bin/bash
set -ex

WORKDIR="/workspace/gateway-image"
OUT_DIR="/workspace/proxy/out"

# 只保留一个 tarball，避免选错
TARBALLS=($(ls ${OUT_DIR}/envoy-*.tar.gz 2>/dev/null))
if [ ${#TARBALLS[@]} -eq 0 ]; then
  echo "ERROR: no envoy tarball found in ${OUT_DIR}/"
  exit 1
elif [ ${#TARBALLS[@]} -gt 1 ]; then
  echo "WARNING: multiple tarballs found, please keep only one:"
  ls -la ${OUT_DIR}/envoy-*.tar.gz
  echo "Using newest by modification time..."
fi

TARBALL=$(ls -t ${OUT_DIR}/envoy-*.tar.gz | head -1)
echo "Using tarball: ${TARBALL}"
echo "Tarball size: $(du -h "${TARBALL}" | cut -f1)"

rm -rf "${WORKDIR}"
mkdir -p "${WORKDIR}/amd64"

tar xzf "${TARBALL}" -C "${WORKDIR}/amd64/"

# 验证 envoy 二进制存在且可执行
ENVOY_BIN="${WORKDIR}/amd64/usr/local/bin/envoy"
if [ ! -f "${ENVOY_BIN}" ]; then
  echo "ERROR: envoy binary not found at ${ENVOY_BIN}"
  echo "Tarball contents:"
  tar tzf "${TARBALL}"
  exit 1
fi
echo "Envoy binary size: $(du -h "${ENVOY_BIN}" | cut -f1)"

cat > "${WORKDIR}/Dockerfile" <<'EOF'
FROM registry.cn-shanghai.aliyuncs.com/daofeng/gateway:2.1.12
COPY amd64/usr/local/bin/envoy /usr/local/bin/envoy
EOF

docker build --no-cache -t registry.cn-shanghai.aliyuncs.com/daofeng/gateway:quota-rule "${WORKDIR}"
docker push registry.cn-shanghai.aliyuncs.com/daofeng/gateway:quota-rule

echo "=== GATEWAY IMAGE PUSHED ==="
