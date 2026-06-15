# 故障记录：在 ls-test2 重跑 6/10 e2e 流程，一路踩坑

**日期**：2026-06-15
**环境**：阿里云 ACK，namespace `ls-test2`
**测试人**：lvshui
**目标**：按 [quota-rule-e2e-test-20260610.md](../testing/quota-rule/quota-rule-e2e-test-20260610.md) 的流程在当前环境再跑一遍，验证 6/15 [quota-rule-multi-window-test-20260615.md](../testing/quota-rule/quota-rule-multi-window-test-20260615.md) 列出的 Bug2 / Bug6 是否会复现、是哪种 CRD 形态触发的。

---

## 一、最终结论

| 项 | 结论 |
|---|---|
| Bug2（`rlqs_server.grpc_service` 嵌套） | **不复现** — controller 当前版本直接生成扁平 `rlqs_server.envoy_grpc.cluster_name`。6/15 doc 看到的嵌套大概率是同 tag `pilot:quota-rule` 镜像被覆盖前的版本 |
| Bug6（`Input.typed_config.name` 缺失，listener reject） | **不复现** — controller 当前把 `bucket_matchers` 放在 **per-route `typedPerFilterConfig`**（RateLimitQuotaOverride），且 Input.name = `"request-headers"` 非空。6/15 那次走的是 listener-level filter config 路径才暴露 |
| 6/10 流程能跑通到什么程度 | **链路全通**：CRD → controller → ConfigMap + EnvoyFilter → listener 80 quota filter → quota-server SyncCheck → Redis 精确读到 alice 50/min / bob 200/min。**6/15 当时以为有差异**：quota-server 始终返回 `degraded:true + blanket_rule:ALLOW_ALL` 被怀疑是 bug。**6/15 晚间复测推翻**：这是 SyncCheck 路径的正确响应格式；envoy 确实按 ALLOW_ALL 放行；alice 串行 50 个全 200 → 第 51-60 个 429，精确分布完全复现。压测 0 个 200 的真因是 [坑 10](#坑-10echo-server-在并发-hey-压测下大量返回-400) + 并发下少量请求走 envoy 本地 fallback（见 [坑 9 修订](#坑-9-修订quota-server-始终走-degraded-mode-是设计行为不是-bug)） |

---

## 二、镜像 / 部署对照

| 组件 | 6/10 (ls-test) | 6/15 (ls-test2) | 备注 |
|---|---|---|---|
| higress-controller | `daofeng/higress:quota-rule` | 同 | |
| pilot (discovery) | `daofeng/pilot:quota-rule` | 同 | tag 可能被覆盖过 |
| higress-gateway | `daofeng/gateway:quota-rule` | 同 | |
| nginx sidecar | `daofeng/nginx:alpine` | 同 | |
| **quota-server** | `daofeng/ratelimit-quota-server:latest` | **`tz-fix-20260615`**（本次手 build）| `latest` 的 digest 飘动；曾出现过 panic 版本 |
| Redis | ls-test 的 redis-builtin (auth `f5aa5a6298924a63`) | `redis-builtin.higress-system:6379` (auth `1905b762fd25c8a5`) | 6/15 CRD 一度写错指向 apigateway-system |

quota-server 新镜像 build 步骤见第六节。

---

## 三、踩坑全记录（按发生顺序）

### 坑 0：6/15 多窗口测试遗留的 ConfigMap / domain / Redis 三方不一致

| 项 | 内容 |
|---|---|
| 现象 | controller args 里硬编码 `--clusterID=istio`（flag 优先级高于 env `CLUSTER_ID=Kubernetes`），结果 controller 把 ConfigMap 写到 `istio-ratelimit-config`、生成 domain `istio-quotarule`；但 quota-server 挂载的是手工创建的 `kubernetes-ratelimit-config`（domain `Kubernetes-quotarule`）。Redis 上 `rl_dc:Kubernetes-quotarule:*` 永远没人读 |
| 解决 | `kubectl patch deploy/higress-controller --type=json -p='[{"op":"replace","path":"/spec/template/spec/containers/0/args/8","value":"--clusterID=Kubernetes"}]'`；同时手工把 6/15 写的 limits_json key 备份后删掉 |
| 备份 | `/tmp/quota-test-20260615-rollback/` 留了 CRD + Redis dump |

### 坑 1：controller 报 `envoy endpoints length is 0, don't push quotarule to envoy`

| 项 | 内容 |
|---|---|
| 现象 | CRD apply 后，controller debug 日志 `warn quotarule envoy endpoints length is 0`，ConfigMap / EnvoyFilter 都不下发 |
| 真正根因 | `quotarule.go:54-63 GetEndpointsName()` 用 `strings.Replace(features.ClusterName, "istio", "envoy-hs", 1)`。当 `CLUSTER_ID=Kubernetes` 时，字符串里没有 "istio" 子串，replace 直接返回 `Kubernetes`，controller 去查名为 `Kubernetes` 的 endpoints —— 当然找不到 |
| 解决 | env 加 `QUOTA_GATEWAY_ENDPOINTS_NAME=envoy-hs`（这个 env 优先级最高，绕开 Replace 逻辑）。memory 里的 6/10 部署清单本来就有这一条，6/15 在 ls-test2 部署时被漏掉了 |
| 源码风险 | 这个 Replace 逻辑只对 `istio` 或 `*-istio` 这种 cluster-id 有效，应该改成"显式 env 优先 + 默认 `envoy-hs`"，或者用更稳定的 svc selector |

### 坑 2：controller reconcile pod 间 cache 分裂

| 项 | 内容 |
|---|---|
| 现象 | controller 2 副本部署。一个 pod 看到 `envoyFilterResources=2 gatewayEnvoyEndpointCount=1` 正常 reconcile；另一个 pod 同时刻报 `envoy endpoints length is 0` |
| 影响 | 不工作的那个 pod 推空给 pilot，pilot 视图里 quota EnvoyFilter 时有时无 |
| 解决 | 把那个 pod 直接 `kubectl delete pod`，新 pod 起来后 endpoints informer 重新 warmup，2 个 pod 状态一致 |
| 推断 | endpoints informer 在 pod 早期没 warm up 完成时被注入到 quotarule reconcile 路径，cache 长期 stale。需要 informer ready 判断（`cacheSynced` 之类）才允许 reconcile |

### 坑 3：controller 自己生成的 global EnvoyFilter 在 LDS 里"时有时无"

| 项 | 内容 |
|---|---|
| 现象 | pilot `/debug/configz` 能看到 controller 内存里的 `quotarule-global-config` EnvoyFilter（HTTP_FILTER + CLUSTER 2 个 patch，无 workloadSelector）；但 envoy listener 80 chain 上没有 quota filter，pilot 自己的 `/debug/config_dump?proxyID=...` 视图里也没有 |
| 复现模式 | gateway pod 重启后，需要 controller 重启 + 触发 CR reconcile，listener 80 才有 quota filter；中间任意一次 CR 变更，可能让 listener 80 上的 quota filter 消失 |
| 临时绕开 | 手工 apply 一个带 `workloadSelector` + `portNumber: 80` 的 K8s EnvoyFilter（内容跟 controller 想生成的等价），pilot 自动 watch 后立刻 patch listener 80 |
| 留作后续 | 真根因在 controller 端如何把内存 EnvoyFilter 暴露给 pilot 的 config store。可能 6/10 跑通靠的是 pod 启动顺序刚好让这个 push 成功了 |

### 坑 4：envoy listener 80 上的 wasm key-auth filter 阻塞所有 LDS update

| 项 | 内容 |
|---|---|
| 现象 1 | envoy stats `listener_manager.lds.update_rejected: 3`；discovery 日志 `ADS:LDS: ACK ERROR ... Internal: Error adding/updating listener(s) 0.0.0.0_80: Unable to create Wasm HTTP filter ls-test2.key-auth.internal` |
| 现象 2 | gateway 日志反复刷 `wasm log: [extensions/key_auth/plugin.cc:68] parsePluginConfig() No consumers and no credentials` |
| 根因 | `WasmPlugin/ls-test2/key-auth.internal` 的 `defaultConfig` 只有 `{global_auth:false, in_header:true, keys:[Authorization, x-api-key]}`，缺 `consumers`。plugin parseConfig 失败 → ECDS 推给 envoy 时 wasm runtime 拒创建 → 整个 listener 80 update 被 reject → quota filter 也跟着进不去 |
| 用户经验值 | "一个 wasmplugin 错误会阻塞所有 wasmplugin 下发" 是已知行为 |
| 解决 | `kubectl patch wasmplugin -n ls-test2 key-auth.internal --type=merge -p='{"spec":{"defaultConfigDisable":true}}'` |
| 留作后续 | controller 应该在 wasm config validate 失败时跳过推送，而不是把整个 listener 一起拖死 |

### 坑 5：envoy server.state 永远 INITIALIZING，pod 不 ready

| 项 | 内容 |
|---|---|
| 现象 | 新 gateway pod 启动 5+ 分钟，envoy admin `/ready` 返回 503 `INITIALIZING`，readiness probe 持续失败；旧 pod 没被 rolling update 删掉 |
| `/init_dump` 提示 | `shared target FilterConfigSubscription init ls-test2.key-auth.internal` —— listener 80 在等 key-auth ECDS init |
| 嵌套根因 | controller 处理 `WasmPlugin.spec.url=http://higress-plugin-server/...` 时，需要 fetch wasm bytes。controller pod 在 `ls-test2` ns，DNS 解析 `higress-plugin-server`（短名）会查 `higress-plugin-server.ls-test2.svc.cluster.local` —— 这个 svc **在 ls-test2 ns 不存在**，只在 `higress-system` / `apigateway-system` / `aigw-anchor` 等 ns 有 |
| 解决 1 | `kubectl apply` 一个 `ExternalName` svc 把 `higress-plugin-server` 映射到 `higress-plugin-server.higress-system.svc.cluster.local` |
| 解决 2 | 临时把 gateway 的 readinessProbe 从 `curl http://localhost:15000/ready` 改成 `tcpSocket port 80` —— envoy 80 已 listen 直接 pass，pod ready，rolling update 解锁 |
| 留作后续 | 新 ns 部署时这个 ExternalName 应该进 helm chart 或 cluster bootstrap，不应该手工补 |

### 坑 6：ingress → envoy 路由 SRDS scope 数量为 0

| 项 | 内容 |
|---|---|
| 现象 | listener 80 上 `scoped_rds.active_scopes: 0, all_scopes: 0`；envoy 上 `outbound\|80\|\|echo-server` cluster 不存在；SLB 8.156.95.31 打任何路径返 404 |
| 根因 | higress controller 把 echo-server ingress 转成 VirtualService 时，gateways 字段写的是 `"ls-test2/61af79b04c9c8e70"`，但实际生成的 Gateway 资源叫 `Kubernetes-61af79b04c9c8e70`（带 `--clusterID` 前缀）。两者名字对不上，pilot SRDS 生成不出 scope |
| 解决 | 手工 apply 一个 istio 标准 `Gateway` + `VirtualService` 资源（名字、selector 都明示给出），绕开 higress 的 ingress 转换。SRDS 立刻有 1 scope，envoy 拿到 echo-server cluster，SLB 路径打通 |
| 留作后续 | controller 在 ingress → VS 转换时 gateways 字段引用应该和 Gateway 资源命名一致（要么都带 cluster_id 前缀，要么都不带） |

### 坑 7：quota-server `latest` tag 飘动 + 实际跑的 image 缺 timezone fix

| 项 | 内容 |
|---|---|
| 现象 | listener / quota filter 都通了，curl 进来 envoy 直接 429 `quota_rate_limited`。quota-server log: `PANIC RECOVERED in StreamRateLimitQuotas.worker: time: missing Location in call to Time.In`，调用栈在 `calendarWindowBounds:80`（`time.Unix(...).In(loc)`，`loc=nil`）|
| 历史背景 | 6/10 doc Bug 2 已经记录过这个 panic，"修复"两件：Dockerfile 装 tzdata + 代码 `resolveTimezoneLocation()` nil 时 fallback `time.UTC`。memory 写明 "代码层面修复已改本地但未编译部署" |
| 当前镜像 sha | `sha256:2f03907d...`（早期 latest）→ 改 imagePullPolicy=Always force pull 后变 `sha256:f888f1ad...`（某次中间 build）。**latest 完全靠不住** |
| 解决 | 见第六节：本地编译当前源码（含 nil fallback），build 推 stable tag `tz-fix-20260615`，部署改用这个 tag |
| 教训 | 任何长生命周期环境都不要依赖 `latest`，build 一律带 `<commit>-<date>` 形式的 immutable tag |

### 坑 8：quota-server config watcher 只 reload 一部分

| 项 | 内容 |
|---|---|
| 现象 | controller 把 ConfigMap 从静态 `bucket_id: {test-any-header: ""}` 改成动态 `bucket_id: {cu: '*'}` + `parallel_dimensions` 后，quota-server log 出现 `Config file changed, reloading: ... Control-plane lookup config reloaded`，但 SyncCheck 时还是按旧的 `test-any-header__100_minute_request` 行为，新 bucket_action 没生效 |
| 表现 | envoy SyncCheck `bucket=map[cu:alice]` → quota-server log `unknown bucket_id 'cu_alice' in ratelimit quota server config` → 返回 degraded + ALLOW_ALL |
| 解决 | `kubectl delete pod` 强制 quota-server 重启，重新 `Parsed YAML` 加载完整新配置（这次能看到 `bucket_action: cu_*_100_minute_request`、`wildcardKeys` 收集正确） |
| 留作后续 | watcher 应该 reload 全部域配置而不只是 control-plane 部分；最起码出现 `unknown bucket_id` 时主动重 parse |

### 坑 9：quota-server 始终走 degraded mode，envoy 落到本地 fallback

> ⚠️ **2026-06-15 晚间复测推翻这个判断**，见下方 [坑 9 修订](#坑-9-修订quota-server-始终走-degraded-mode-是设计行为不是-bug)。
> 以下保留原文作为当时的判断历史。

| 项 | 内容 |
|---|---|
| 现象 | SyncCheck 成功读到 Redis 配额（alice remaining=49 / bob remaining=199），但响应 body 里 `rate_limit_strategy: {blanket_rule: ALLOW_ALL} degradation_info: {degraded:true, global_remaining_tokens:N, strict_request_mode:true}`。envoy 拿到这个响应后**没有按 ALLOW_ALL 放行**，而是落到 `no_assignment_behavior.fallback_rate_limit.token_bucket`（controller 在 per-route override 里写的是 100 tokens / 60s） |
| 影响 | 压测 alice 50/min + bob 200/min 出来的结果 ≈ 0 通过 + 几百 429（fallback bucket 被前一批 bob 压测耗尽，后来 alice 拿不到 token）。复现不出 6/10 doc 写的 "50 OK + 50 rate-limited" 这种精确分布 |
| 留作后续 | quota-server 在能从 Redis 拿到精确配额时应该返回精确 `token_bucket` 给 envoy 而不是 blanket ALLOW_ALL + degraded。这个改动在 quota-server 源码层面，需要看 `handleSyncCheck` 路径上 `degraded` 标记的设置逻辑 |

### 坑 9 修订：quota-server 始终走 degraded mode 是设计行为，不是 bug

**复测时间**：2026-06-15 18:30+，同 ls-test2 环境，quota-server 镜像 `tz-fix-20260615` 未改动

**复测结论**：原坑 9"quota-server 是 bug"的判断**错了**，不需要改 quota-server 源码。

| 项 | 内容 |
|---|---|
| 实测 1：串行单请求 | 6 个 curl（alice 3 + bob 3）全部 200 OK，Redis 计数器精确递减 |
| 实测 2：alice 串行 50+10 | 前 50 个 200 OK + 第 51-60 个 429（quota-server log `allowed=false, remaining=0`）。**精确分布完全复现** |
| 实测 3：bob 串行 30 | 30 个全部 200 OK（bob 配额 200/min 未耗尽，符合预期） |
| 实测 4：alice hey -n60 -c10 | quota-server log 36 次 SyncCheck **全部 allowed=true**；envoy access log 显示 10 个 `429 quota_rate_limited (RL flag)`，**没问 quota-server**；20 个 `400 via_upstream`（echo-server 后端 400，对应坑 10） |
| 代码层验证 | `ratelimit-quota-server/src/service/ratelimit_quota.go:702 buildSyncCheckResponse()` 明确同时设置 `BlanketRule (ALLOW_ALL/DENY_ALL)` + `DegradationInfo.Degraded=true`，注释写 `// SyncCheck only happens in degraded mode`。这是 SyncCheck 路径的**正确响应格式**：BlanketRule = 此请求的 ALLOW/DENY 决定，Degraded = "维持降级状态，下个请求继续走 SyncCheck" |
| envoy 实际行为 | 收到 `ALLOW_ALL + Degraded:true` **正确放行**。原坑 9 推断"envoy 没按 ALLOW_ALL 放行"是误判，无直接证据 |

**6/15 当时压测"0 个 200"的真正成因**（两件独立的事叠加）：
1. **坑 10（已正确识别）**：echo-server 在并发 hey 下大量返回 400（envoy access log `via_upstream`），跟限流链路无关
2. **envoy apig filter 并发行为**（6/15 当时漏判）：并发下部分请求**绕过 SyncCheck**，被 envoy 本地 `no_assignment_behavior.fallback_rate_limit.token_bucket`（100/60s 共享桶）拦截 → 真实复测仍能稳定看到几个 `RL flag` 的 429。**这不是 quota-server 的问题，是 envoy 端 hot-bucket / CachedBucket 在 burst 期间未及时建立时的兜底行为**。要进一步研究的话挖 envoy 端 `GlobalHotspotTracker` 和 `CachedBucket` 在 TLS publish 之前的请求路径

**对源码 / 镜像的修复建议**：
- ❌ 不要改 `handleSyncCheck` / `buildSyncCheckResponse` —— 当前实现是对的
- ✅ 后续 envoy 行为深挖（可选）：看 apig filter 在并发 burst 下绕过 SyncCheck 的概率，是否能调阈值让它早点切到 SyncCheck 路径
- ✅ 测试基础设施：换更宽容的 backend（替代 echo-server），坑 10 的 400 才不会污染测试结论

### 坑 10：echo-server 在并发 hey 压测下大量返回 400

| 项 | 内容 |
|---|---|
| 现象 | hey -n 100 -c 20 时大量 `response_code: 400, response_code_details: via_upstream`（envoy 已经把请求送到 echo-server，echo-server 自己返 400）|
| 单 curl | 直接 `curl /echo` 返 200 OK |
| 推断 | echo-server 后端对 hey 的 default headers / Connection: close 行为不友好。跟 quota 链路无关，单独看 |
| 留作后续 | 换更宽容的 echo backend（busybox httpd 之类）做压测后端，避免误判 |

---

## 四、Ad-hoc 修复后的 ls-test2 实际状态

如下都是手工动的，跟 helm chart 不同步，**下次 helm upgrade 会被覆盖**：

| 资源 | 状态 |
|---|---|
| `deploy/higress-controller` args | `--clusterID=Kubernetes`（patch from `istio`）|
| `deploy/higress-controller` env (higress container) | 新增 `QUOTA_GATEWAY_ENDPOINTS_NAME=envoy-hs` |
| `deploy/higress-gateway` quota-server container | image=`registry.cn-shanghai.aliyuncs.com/daofeng/ratelimit-quota-server:tz-fix-20260615`, imagePullPolicy=Always |
| `deploy/higress-gateway` higress-gateway container | readinessProbe 改成 `tcpSocket port 80`（原来是 `exec curl /ready`，会卡 INITIALIZING）|
| `cm/higress-config` | `mcpServer.redis.{address,password}` 从 `redis-builtin.ls-test:6379 / f5aa5a6298924a63` 改成 `redis-builtin.higress-system:6379 / 1905b762fd25c8a5` |
| `svc/higress-plugin-server`（新建）| ExternalName → `higress-plugin-server.higress-system.svc.cluster.local` |
| `wasmplugin/key-auth.internal` | `spec.defaultConfigDisable: true`（patch） |
| `gateway/echo-server-gateway` + `virtualservice/echo-server-vs`（新建）| 给 listener 80 提供 echo-server 路由 |
| `quotarule/test-quota` | 6/10 动态形态（dimensions + dynamic + target echo-server） |
| Redis `rl_dc:Kubernetes-quotarule:cu_alice` / `cu_bob` | 50/min / 200/min request 配置 |

备份文件目录：`/tmp/quota-test-20260615-rollback/`
- `quotarule-multi-window-test.yaml`（6/15 原 CRD）
- `higress-config-before.yaml`
- `quotarule-dynamic-consumer.yaml`（6/10 形态 CRD）
- `quotarule-static-100min.yaml`（一开始试的静态 CRD）
- `echo-server-vs-gw.yaml`
- `redis-keys.txt` / `redis-rl-dc-dump.txt`

---

## 五、6/15 doc 里 Bug2 / Bug6 假设的修订

| 6/15 假设 | 当前观察 |
|---|---|
| Bug2：controller 端 `RlqsServer` 在 `BuildHTTPFilter` 时 protobuf JSON marshal 多套一层 `grpc_service` | 当前 controller 镜像的输出是扁平的 `rlqs_server.envoy_grpc.cluster_name`，源码也 OK。**6/15 看到的嵌套大概率是同 tag `pilot:quota-rule` 镜像被覆盖前的旧版本** —— 这条 bug 在镜像层面已经修了 |
| Bug6：controller 构造 `Matcher_MatcherList_FieldMatcher.SinglePredicate.Input` 时 `Input.Name` 漏填，导致 envoy 拒 listener | controller 当前把 bucket_matchers 放在 **per-route `typedPerFilterConfig`**（RateLimitQuotaOverride），且 `input.name = "request-headers"` 非空。**这条路径不会触发 Bug6**。<br>6/15 那次触发是因为 multi-window-test 形态走的是 **listener-level filter config（RateLimitQuotaFilterConfig.bucket_matchers）** 的路径，那条路径 Input.name 没填 |
| 推论 | 想验证 Bug6 是否还存在，需要造一个能让 controller 走 **listener-level bucket_matchers** 的 CRD（推测是 `limits_json` 多窗口 + 某种 spec.rules 结构）；单 dimension 动态形态走 per-route，不暴露 |

---

## 六、quota-server 镜像 build & 部署（已沉淀）

### 6.1 源码状态

| 文件 | 改动 |
|---|---|
| `ratelimit-quota-server/go.mod` | `replace github.com/envoyproxy/go-control-plane => ../csb2-go-control-plane`（HEAD 是指 alibaba 内网 gitlab proxy，外部环境拉不到；working tree 之前指错到 `../envoy/go-control-plane` 没那个包）|
| `ratelimit-quota-server/src/utils/window_bounds.go` | `resolveTimezoneLocation()` 已含 nil fallback `time.UTC` 分支（line 162 / 175），跟 memory 写的"已改本地但未编译部署"对得上 |
| `ratelimit-quota-server/Dockerfile` | 已含 `apt-get install -y tzdata` |

### 6.2 build 步骤（macOS Apple Silicon，目标 linux/amd64）

```bash
cd /Users/lvshui/Dev/code_repo/higress-opensource/ratelimit-quota-server

# 1. cross-compile go binary
export http_proxy=http://11.165.113.219:1087
export https_proxy=http://11.165.113.219:1087
export GOOS=linux GOARCH=amd64 CGO_ENABLED=0
/opt/homebrew/bin/go build -mod=mod -ldflags="-s -w" \
  -o ./bin/ratelimit-quota \
  github.com/envoyproxy/ratelimit-quota/src/service_cmd

# 2. 首次构建需要先装 QEMU emulator（Lima VM 是 arm64）
DOCKER=/Users/lvshui/.lima/_bin/docker
$DOCKER run --privileged --rm tonistiigi/binfmt --install amd64
$DOCKER buildx create --name cross-builder --driver docker-container --use 2>/dev/null || $DOCKER buildx use cross-builder

# 3. docker build amd64 + push
IMG=registry.cn-shanghai.aliyuncs.com/daofeng/ratelimit-quota-server:tz-fix-20260615
$DOCKER buildx build --platform linux/amd64 -t "$IMG" --load .
$DOCKER push "$IMG"
# digest: sha256:d71e48e94f2c3d91a93dc29f4dd00eacbbbb92d3302d20bd39edb61d908ff379
```

### 6.3 部署

```bash
kubectl set image -n ls-test2 deploy/higress-gateway \
  quota-server=registry.cn-shanghai.aliyuncs.com/daofeng/ratelimit-quota-server:tz-fix-20260615
kubectl patch deploy higress-gateway -n ls-test2 --type=json \
  -p='[{"op":"replace","path":"/spec/template/spec/containers/2/imagePullPolicy","value":"Always"}]'
```

---

## 七、教训

1. **`latest` tag 在长期运行环境里不可信** —— 6/10 跑通是当时 latest 的某个版本，几周后 latest 可能 sha 变了内容变了。所有可重现的部署必须用 `<commit>-<date>` 形式的 immutable tag
2. **CLUSTER_ID 影响半个项目** —— ConfigMap 名、domain、Endpoints 查找名（通过 `strings.Replace`）、ingress→VS gateways 引用名都跟它有关。修改前必须把这 4 个地方一起对齐
3. **higress 在新 ns 部署的最小可工作 checklist 缺项**：
   - `QUOTA_GATEWAY_ENDPOINTS_NAME=envoy-hs` env
   - `WATCH_RESOURCES_BY_NAMESPACE_FOR_PRIMARY_CLUSTER=<ns>` env
   - `ExternalName svc higress-plugin-server` 跨 ns 引到 higress-system
   - 至少一个非空 consumer 的 key-auth WasmPlugin 配置（或 `defaultConfigDisable: true`）
4. **envoy listener wasm filter 解析失败会拖死整个 listener** —— controller 端必须在 wasm config validate 失败时降级（跳过推送 / 推送空配置），否则整个 listener update 链路被卡
5. **controller global EnvoyFilter 推送链路有时序问题** —— 临时绕开是手工 apply 一个等价的 K8s EnvoyFilter（带 `workloadSelector` + `portNumber` match），靠 pilot 自己的 watch 链路。长期需要看 controller 端怎么把内存 EnvoyFilter 持久化进 pilot config store
6. **新建 ns 时优先复用其他 ns 已经踩平的部署模板**（如 higress-system-dev / aigw-anchor），通过 diff 找出缺项；从空 helm chart 起步反而容易漏配
7. **kubectl exec ls/cat 在镜像是 distroless + 跨 arch 镜像时会 "exec format error"** —— 不是 pod 坏，是镜像里没有/不兼容的 shell 工具。改用 `kubectl logs` + `curl --` 探测，或者 sidecar debug 容器
