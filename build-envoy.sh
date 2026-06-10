#!/bin/bash
set -ex

# Usage:
#   sh build-envoy.sh              # 全量构建 release envoy
#   sh build-envoy.sh test         # 快速验证 apig filter
# 查看日志: docker logs -f envoy-builder
# 查看状态: docker ps | grep envoy-builder

MODE="${1:-full}"
CONTAINER_NAME="envoy-builder"
IMAGE="higress-registry.cn-hangzhou.cr.aliyuncs.com/higress/build-tools-proxy:release-1.19-ef344298e65eeb2d9e2d07b87eb4e715c2def613"
BAZEL_ARGS="--override_repository=envoy=/home/envoy --@envoy//contrib/network/connection_balance/dlb/source:enabled=false"

docker volume create bazel-cache 2>/dev/null || true

# 清理旧容器
docker rm -f "${CONTAINER_NAME}" 2>/dev/null || true

if [ "$MODE" = "test" ]; then
  BUILD_CMD="bazel build ${BAZEL_ARGS} @envoy//source/extensions/filters/http/rate_limit_quota_apig:config && echo '=== TEST BUILD OK ==='"
else
  BUILD_CMD="set -e && SHA=\$(git rev-parse HEAD) && bazel build ${BAZEL_ARGS} --config=release //:envoy_tar && BAZEL_OUT=\$(bazel info ${BAZEL_ARGS} output_path)/k8-opt/bin && cp -f \${BAZEL_OUT}/envoy_tar.tar.gz /home/envoy-alpha-\${SHA}.tar.gz && mkdir -p /work/out && cp -f /home/envoy-alpha-\${SHA}.tar.gz /work/out/ && echo '=== BUILD DONE ===' && ls -la /work/out/envoy-*.tar.gz"
fi

docker run -d \
  --name "${CONTAINER_NAME}" \
  -v /workspace/proxy:/work \
  -v /workspace/envoy:/home/envoy \
  -v bazel-cache:/home/.cache \
  -w /work \
  -e CC=clang -e CXX=clang++ \
  "${IMAGE}" \
  bash -c "${BUILD_CMD}"

echo ">>> 后台构建已启动"
echo ">>> 查看日志: docker logs -f envoy-builder"
