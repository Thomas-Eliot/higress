#!/bin/bash
set -ex

# 用命名 volume 持久化 bazel 缓存
docker volume create bazel-cache 2>/dev/null || true

# 如果容器已存在，直接 start + exec；否则创建新容器
if docker ps -a --format '{{.Names}}' | grep -q '^envoy-builder$'; then
  docker start envoy-builder 2>/dev/null || true
  docker exec envoy-builder bash -c '
    mkdir -p /home/package
    make test_release
    mkdir -p /work/out
    cp /home/package/envoy-*.tar.gz /work/out/ 2>/dev/null || true
    echo "=== BUILD DONE ==="
    ls -la /home/package/envoy-*.tar.gz
  '
else
  docker run --name envoy-builder \
    -v /workspace/proxy:/work \
    -v /workspace/envoy:/home/envoy \
    -v bazel-cache:/home/.cache \
    -w /work \
    -e BUILD_ENVOY_BINARY_ONLY=1 \
    -e CC=clang -e CXX=clang++ \
    -e "BAZEL_BUILD_ARGS=--override_repository=envoy=/home/envoy --@envoy//contrib/network/connection_balance/dlb/source:enabled=false" \
    higress-registry.cn-hangzhou.cr.aliyuncs.com/higress/build-tools-proxy:release-1.19-ef344298e65eeb2d9e2d07b87eb4e715c2def613 \
    bash -c '
      mkdir -p /home/package
      make test_release
      mkdir -p /work/out
      cp /home/package/envoy-*.tar.gz /work/out/ 2>/dev/null || true
      echo "=== BUILD DONE ==="
      ls -la /home/package/envoy-*.tar.gz
    '
fi
