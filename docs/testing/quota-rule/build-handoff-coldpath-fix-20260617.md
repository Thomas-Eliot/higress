# 构建交接：gateway 冷路径 0ms-timeout 修复重编（在 amd64 机器执行）

**日期**：2026-06-17
**目的**：重编 gateway 镜像，修掉「配额冷路径 sync-check 生效 timeout≈0ms → 低速永远 429」。
**结论**：**无需改任何代码**，从 `csb2/envoy@envoy-1.27` **分支 tip = `ea658b64be`** 重编即可。该 tip 已含修复；线上跑的是 squash 前的 orphan commit `e541c3`（已从远端消失）才有 bug。

---

## 为什么是重编（根因一句话）

线上 gateway 二进制冷路径计时器 `enableTimer(0)`，发出 sync-check 后 ~245μs 就「timed out」→ reset 流 → fallback=deny → 429；quota-server 其实 5~8ms 能判 ALLOW，永远来不及。已用 EnvoyFilter 注入 `cold_sync_timeout=1s` 验证：低速 10/10 → 200，`cold_path_sync_error`/`rate_limited` 零新增。详见 [issue-coldpath-synccheck-always-deny-20260617.md](./issue-coldpath-synccheck-always-deny-20260617.md)。

当前 tip `ea658b64be` 已有两处正确实现（无需再改）：
- `source/extensions/filters/http/rate_limit_quota_apig/filter.cc:90` `coldPathTimeoutValue` 默认 **20ms**（不是 0）。
- 同文件 `:642` 冷路径返回 **`StopIteration`**（阻塞等 sync 结果 → 既消除误杀，又恢复同步 enforce）。

> ⚠️ 本地 HEAD == 远端 `csb2/envoy@envoy-1.27` tip == `ea658b64be1097404d8824cad58dabee651a5446`（已 `git ls-remote` 核对）。**别用子模块记录的 `e541c3…`（orphan、已删、含 bug）；用分支 tip。**

---

## 在 amd64 机器上的步骤

### 0. 两份源码（注意来源）
```bash
mkdir -p /workspace && cd /workspace
# proxy（istio-1.19，提供 //:envoy_tar 构建目标）
git clone --depth 1 https://github.com/higress-group/proxy.git -b istio-1.19
# envoy —— 必须是 csb2/envoy@envoy-1.27 tip（含 apig filter + 本次修复）
git clone https://github.com/Thomas-Eliot/envoy.git -b envoy-1.27 /workspace/envoy   # 若用 github 镜像
# 校验：进 /workspace/envoy 确认 git rev-parse HEAD == ea658b64be…；
#       若镜像落后，改用内网 git@gitlab.alibaba-inc.com:csb2/envoy.git -b envoy-1.27
cd /workspace/envoy && git rev-parse HEAD   # 期望 ea658b64be1097404d8824cad58dabee651a5446
# 再确认两处修复点（必须存在）：
sed -n '90p' source/extensions/filters/http/rate_limit_quota_apig/filter.cc   # return std::chrono::milliseconds(20);
sed -n '642p' source/extensions/filters/http/rate_limit_quota_apig/filter.cc  # return ...StopIteration;
```

### 1. 编 envoy（amd64，bazel，重型）
```bash
docker run --rm --memory=24g \
  -v /workspace/proxy:/work -v /workspace/envoy:/home/envoy \
  -w /work -e BUILD_ENVOY_BINARY_ONLY=1 -e CC=clang -e CXX=clang++ \
  -e "BAZEL_BUILD_ARGS=--override_repository=envoy=/home/envoy --@envoy//contrib/network/connection_balance/dlb/source:enabled=false" \
  higress-registry.cn-hangzhou.cr.aliyuncs.com/higress/build-tools-proxy:release-1.19-ef344298e65eeb2d9e2d07b87eb4e715c2def613 \
  make test_release
# 产物：容器内 /home/package/envoy-alpha-<sha>.tar.gz（已 strip）
```
（等价地，仓库里 `higress-gateway/build-envoy.sh` 也可，但它把产物落到 `/workspace/proxy/out/`。）

### 2. 打 gateway 镜像 —— ⚠️ 用新 tag
线上 gateway 容器 `imagePullPolicy: IfNotPresent`，且旧 `:quota-rule` 是坏 digest（和 `:2.1.13` 同 digest）。**复用同 tag 节点不会重拉**。所以推**新 tag**：

```bash
TAG=quota-rule-coldfix-20260617
mkdir -p out/docker/amd64 && tar xzf envoy-alpha-*.tar.gz -C out/docker/amd64/
cat > out/docker/Dockerfile.gw <<'EOF'
FROM registry.cn-shanghai.aliyuncs.com/daofeng/gateway:2.1.12
COPY amd64/usr/local/bin/envoy /usr/local/bin/envoy
EOF
docker build --platform linux/amd64 -t registry.cn-shanghai.aliyuncs.com/daofeng/gateway:${TAG} \
  -f out/docker/Dockerfile.gw out/docker/
docker push registry.cn-shanghai.aliyuncs.com/daofeng/gateway:${TAG}
# 记下 push 出来的 digest，回来贴给我核对
```
（目标节点只有 amd64，单架构即可；无需 arm64/manifest。）

---

## 部署 + 验证（推完镜像后我来做）

1. 删掉验证用的临时 EnvoyFilter `quota-cold-sync-timeout-probe`（恢复二进制默认 20ms 路径）。
2. `kubectl set image deploy/higress-gateway -n ls-test higress-gateway=…:${TAG}` + `rollout restart`。
3. 低速 0.3s×N 复现：期望 **200**、`cold_path_sync_error` 不再增长、且 `cold_path_sync_allowed` **开始增长**（证明冷路径在阻塞 enforce，而非乐观放行）。
4. 顺带确认超额时仍能 429（server SyncCheck DENY 路径）。

> 旁注：`all-cluster-limit.internal` wasm（qpm=2）是独立干扰项，已删（备份 `/tmp/quota-debug/all-cluster-limit.backup.yaml`），需另查控制台为何下发。
