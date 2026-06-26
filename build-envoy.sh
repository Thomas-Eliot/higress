#!/bin/bash
set -ex

# 在 amd64 构建机执行：编译含 rate_limit_quota_apig filter 的 envoy 二进制。
#
# Usage:
#   sh build-envoy.sh              # 全量构建 release envoy_tar（产物落 /workspace/proxy/out/）
#   sh build-envoy.sh test         # 仅快速编译 apig filter（验证语法/链接，不出 tar）
#
# 前置（构建机上的两份源码，路径固定）：
#   /workspace/proxy   higress proxy 仓库（istio-1.19，提供 //:envoy_tar 目标）
#   /workspace/envoy   本仓 envoy 子模块源码（csb2/envoy@feat/quota-enforce-fix，基于 develop + 本次修复）
#
# 当前修复点（本次：decodeData 持有 body 直到同步配额检查返回）：
#   source/extensions/filters/http/rate_limit_quota_apig/filter.cc  RateLimitQuotaFilter::decodeData
#   commit 11d65def0c（基于 csb2/envoy develop）。务必确认 /workspace/envoy 已 checkout 到含此 commit 的 feat/quota-enforce-fix。
#   （旧 envoy-1.27 线上的等价修复是 commit 257a4a50ad，现已切到 develop 线，多带 100ms 超时/fail-open/多租户。）
#
# 查看日志: docker logs -f envoy-builder
# 查看状态: docker ps | grep envoy-builder

MODE="${1:-full}"
CONTAINER_NAME="envoy-builder"
IMAGE="higress-registry.cn-hangzhou.cr.aliyuncs.com/higress/build-tools-proxy:release-1.19-ef344298e65eeb2d9e2d07b87eb4e715c2def613"
BAZEL_ARGS="--override_repository=envoy=/home/envoy --@envoy//contrib/network/connection_balance/dlb/source:enabled=false"

ENVOY_SRC="/workspace/envoy"
PROXY_SRC="/workspace/proxy"

# 防呆：构建前确认源码里确有本次修复（避免编了个旧 checkout 还以为修好了）。
FILTER_CC="${ENVOY_SRC}/source/extensions/filters/http/rate_limit_quota_apig/filter.cc"
if ! grep -q "RateLimitQuotaFilter::decodeData" "${FILTER_CC}"; then
  echo "ERROR: ${FILTER_CC} 不含 decodeData override —— /workspace/envoy 不是含本次修复的 feat/quota-enforce-fix。"
  echo "       请先在该目录: git fetch && git checkout feat/quota-enforce-fix && git rev-parse HEAD（应含 commit 11d65def0c）"
  exit 1
fi
echo ">>> envoy HEAD: $(cd "${ENVOY_SRC}" && git rev-parse HEAD)"

docker volume create bazel-cache 2>/dev/null || true
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

if [ "$MODE" = "test" ]; then
  BUILD_CMD="bazel build ${BAZEL_ARGS} @envoy//source/extensions/filters/http/rate_limit_quota_apig:config && echo '=== TEST BUILD OK ==='"
else
  BUILD_CMD="set -e && SHA=\$(git -C /home/envoy rev-parse HEAD) && bazel build ${BAZEL_ARGS} --config=release //:envoy_tar && BAZEL_OUT=\$(bazel info ${BAZEL_ARGS} output_path)/k8-opt/bin && cp -f \${BAZEL_OUT}/envoy_tar.tar.gz /home/envoy-alpha-\${SHA}.tar.gz && mkdir -p /work/out && cp -f /home/envoy-alpha-\${SHA}.tar.gz /work/out/ && echo '=== BUILD DONE ===' && ls -la /work/out/envoy-*.tar.gz"
fi

docker run -d \
  --name "${CONTAINER_NAME}" \
  --memory=24g \
  -v "${PROXY_SRC}":/work \
  -v "${ENVOY_SRC}":/home/envoy \
  -v bazel-cache:/home/.cache \
  -w /work \
  -e CC=clang -e CXX=clang++ \
  "${IMAGE}" \
  bash -c "${BUILD_CMD}"

echo ">>> 后台构建已启动"
echo ">>> 查看日志: docker logs -f envoy-builder"
echo ">>> 完成后产物: ${PROXY_SRC}/out/envoy-alpha-<sha>.tar.gz —— 接着跑 sh build-gateway-image.sh <TAG>"
