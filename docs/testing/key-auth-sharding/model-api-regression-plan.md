# Model API 回归测试计划（Key-Auth 分片模式）

**版本**: key-auth-config-sharding  
**测试环境**: ls-test 实例  
**前置条件**: Key-Auth 分片功能已部署（FeatureGate KEY_AUTH_SHARDING >= 2.1.12）  
**关联修复**: commit 3266e1d9a（listStrategyConfigs with scope 在分片模式下返回空）

---

## 测试目标

验证 Key-Auth 分片模式下，Model API 的 CRUD、认证管理、消费者授权等核心功能不受影响。

重点关注：
1. Model API 认证配置的启用/禁用是否正确写入 route-switches ConfigMap
2. 消费者授权到 Model API 后，分片 ConfigMap 的 matchRules 是否正确展开为实际路由
3. 数据面鉴权是否生效

---

## 版本矩阵

由于只有一个测试实例，通过降级→测试→升级的方式覆盖两个版本。降级是测试前置准备动作。

**核心关注点：从 2.1.11 升级到 2.1.12 的兼容性**——用户在 2.1.11 上已有的认证配置和授权关系，升级到 2.1.12 后必须继续生效，不能中断。

| Round | 数据面版本 | 分片模式 | 目的 |
|-------|-----------|---------|------|
| **Round 1** | 2.1.11 | ❌ 非分片 | 模拟用户在旧版本上的正常使用（创建认证、授权消费者） |
| **Round 2** | 2.1.12 | ✅ 分片 | 模拟用户升级后，验证旧数据无缝迁移 + 新功能正常工作 |

### 验证重点差异

| 场景 | 2.1.11（非分片） | 2.1.12（分片） |
|------|-----------------|---------------|
| 启用认证 | key-auth 写入 CR matchRules | key-auth 写入 route-switches ConfigMap |
| 消费者授权 | allow 列表写入 CR matchRules | allow 列表写入 shard ConfigMap |
| listStrategyConfigs with scope | 从 CR 查询 | 从 route-switches 构建 |
| 数据面生效方式 | CR → Istio 直接推送 | ConfigMap → ECDS 推送 |

---

## 测试环境

| 项目 | 值 |
|------|------|
| Admin Service | cop-gateway-admin-svc (47.109.143.5:80) |
| Gateway Service | higress-gateway（需确认新实例 SLB IP） |
| 网关实例 ID | i-v06q4pewoe26o1h5t9ww |
| 实例名称 | ls-test-sharding |
| 数据面 Namespace | ls-test |
| 测试用 Model API | 需新建（旧实例数据已清理） |
| 测试用 Consumer | 需新建或确认已有 |
| Session Cookie | csb-sessionId-GATEWAY=70305c24-adbf-4661-a847-85660c14d159:68230d21-a596-4989-8edf-c925a5a091a1 |

> **重要**：当前环境已降级到 2.1.11（数据库 + 镜像），处于 Round 1 起始状态。

---

## US-MA-1：Model API CRUD 基础操作

| # | 场景 | 操作 | 预期结果 |
|---|------|------|----------|
| 1.1 | 创建 Model API | POST /modelapi/createModelApi | code=200，返回 ID（model-api-{apiName}） |
| 1.2 | 查询详情 | POST /modelapi/getModelApi | 返回完整配置，字段与创建时一致 |
| 1.3 | 列表查询 | POST /modelapi/listModelApis | total 正确，分页正常 |
| 1.4 | 更新 Model API | POST /modelapi/updateModelApi（修改 description） | code=200，详情查询确认更新生效 |
| 1.5 | 更新不覆盖认证配置 | 更新后查询详情 | authenticationConfig 保持不变（不被 null 覆盖） |
| 1.6 | 删除 Model API | POST /modelapi/deleteModelApi | code=200，再查询返回 not found |
| 1.7 | 删除后路由清理 | kubectl 查询关联 ingress | 对应路由已删除 |

### 验证命令

```bash
# 1.1 创建
curl -s 'http://47.109.143.5/api/gateway/modelapi/createModelApi' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{
    "gwInstanceId":"i-lci63hlysglgtpry1sjq",
    "apiName":"regression-crud-test",
    "description":"CRUD regression test",
    "basePath":"/api","basePathRemove":true,
    "methodPathList":[{"path":"/v1/chat/completions","method":"POST"}],
    "protocol":"OPENAI_COMPATIBLE","sceneType":"TEXT_GENERATION",
    "routeDispatcher":{"strategyType":"HEADER","rules":[{"headerMatch":{"x-higress-llm-model":"regression/qwen-plus"},"weightRuleList":[{"weight":100,"serviceId":"hi-service-bailian-native","serviceName":"bailian-native"}]}]},
    "observationConfig":{"enable":true,"logRequestInfo":true,"logResponseInfo":true}
  }'

# 1.2 查询详情
curl -s 'http://47.109.143.5/api/gateway/modelapi/getModelApi' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{"gwInstanceId":"i-lci63hlysglgtpry1sjq","id":"model-api-regression-crud-test"}'

# 1.4 更新
curl -s 'http://47.109.143.5/api/gateway/modelapi/updateModelApi' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{
    "gwInstanceId":"i-lci63hlysglgtpry1sjq",
    "id":"model-api-regression-crud-test",
    "apiName":"regression-crud-test",
    "description":"CRUD regression test - updated",
    "basePath":"/api","basePathRemove":true,
    "methodPathList":[{"path":"/v1/chat/completions","method":"POST"}],
    "protocol":"OPENAI_COMPATIBLE","sceneType":"TEXT_GENERATION",
    "routeDispatcher":{"strategyType":"HEADER","rules":[{"headerMatch":{"x-higress-llm-model":"regression/qwen-plus"},"weightRuleList":[{"weight":100,"serviceId":"hi-service-bailian-native","serviceName":"bailian-native"}]}]},
    "observationConfig":{"enable":true,"logRequestInfo":true,"logResponseInfo":true}
  }'

# 1.6 删除
curl -s 'http://47.109.143.5/api/gateway/modelapi/deleteModelApi' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{"gwInstanceId":"i-lci63hlysglgtpry1sjq","id":"model-api-regression-crud-test"}'
```

---

## US-MA-2：认证管理（启用/禁用）

每个认证相关步骤需要同时验证：
- **管理面 API 响应**：接口返回 code=200
- **CR/ConfigMap 结构**：WasmPlugin CR matchRules 为空（分片预期）、route-switches 或 CR 中有对应路由的 key-auth 配置
- **数据面行为**：client 实际请求 gateway，根据 HTTP status code 判断鉴权是否生效

| # | 场景 | 操作 | 管理面预期 | CR/ConfigMap 预期 | 数据面预期 |
|---|------|------|-----------|------------------|-----------|
| 2.1 | 启用认证 | changeModelApiAuthStatus enable=true | code=200 | WasmPlugin CR matchRules 仍为空（分片模式不写 CR matchRules）；CR 中有该路由的 key-auth matchRule（Model API 走 KeyAuthPluginHandler 直接写 CR） | — |
| 2.2 | 启用后查询详情 | getModelApi | authenticationConfig.enable=true, credentialTypeList=["API_KEY"] | — | — |
| 2.3 | 启用后 CR 结构验证 | kubectl get wasmplugin | — | spec.matchRules 中包含 model-api 路由的 key-auth 条目（configDisable=false, ingress=[routeName]） | — |
| 2.4 | 启用后数据面-无 key | client 请求 gateway | — | — | **401**（鉴权已启用，无 key 被拒） |
| 2.5 | 启用后数据面-有效 key | client 带已授权 consumer key 请求 | — | — | **200**（鉴权通过） |
| 2.6 | 禁用认证 | changeModelApiAuthStatus enable=false | code=200 | CR matchRules 中该路由条目 configDisable=true 或被移除 | — |
| 2.7 | 禁用后 CR 结构验证 | kubectl get wasmplugin | — | 该路由的 key-auth matchRule configDisable=true | — |
| 2.8 | 禁用后数据面-无 key | client 请求 gateway | — | — | **200**（鉴权已禁用，放行） |
| 2.9 | 重新启用认证 | changeModelApiAuthStatus enable=true | code=200 | CR matchRules 恢复 configDisable=false | — |
| 2.10 | 重新启用后数据面-无 key | client 请求 gateway | — | — | **401** |

### 验证命令

```bash
# 2.1 启用认证
curl -s 'http://47.109.143.5/api/gateway/modelapi/changeModelApiAuthStatus' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{
    "gwInstanceId":"i-lci63hlysglgtpry1sjq",
    "id":"model-api-test-regression-api",
    "authenticationConfig":{"enable":true,"credentialTypeList":["API_KEY"]}
  }'

# 2.3 CR 结构验证 - 检查 WasmPlugin CR 中 model-api 路由的 matchRules
kubectl get wasmplugin key-auth.internal -n ls-test -o json | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
spec=d['spec']
print('=== WasmPlugin CR 分片状态 ===')
print('matchRules:', 'EMPTY' if not spec.get('matchRules') else f'{len(spec[\"matchRules\"])} rules')
print('resourceRefs:', len(spec.get('resourceRefs',[])), 'refs')
if spec.get('matchRules'):
    for rule in spec['matchRules']:
        ingress = rule.get('ingress', rule.get('_matchRoute',[]))
        if any('model-api-test-regression' in str(r) for r in ingress):
            print(f'  FOUND: {rule}')
"

# 2.4 数据面验证-无 key（启用后应返回 401）
curl -s -o /dev/null -w '%{http_code}' 'http://8.156.87.83/api/v1/chat/completions' \
  -H 'Content-Type: application/json' \
  -H 'x-higress-llm-model: test-regression/qwen-plus' \
  -d '{"model":"qwen-plus","messages":[{"role":"user","content":"hi"}]}'

# 2.5 数据面验证-有效 key（启用后应返回 200）
curl -s -o /dev/null -w '%{http_code}' 'http://8.156.87.83/api/v1/chat/completions' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer g7ihtvme7e5liwpmd5ld' \
  -H 'x-higress-llm-model: test-regression/qwen-plus' \
  -d '{"model":"qwen-plus","messages":[{"role":"user","content":"hi"}]}'

# 2.6 禁用认证
curl -s 'http://47.109.143.5/api/gateway/modelapi/changeModelApiAuthStatus' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{
    "gwInstanceId":"i-lci63hlysglgtpry1sjq",
    "id":"model-api-test-regression-api",
    "authenticationConfig":{"enable":false,"credentialTypeList":["API_KEY"]}
  }'

# 2.7 禁用后 CR 结构验证
kubectl get wasmplugin key-auth.internal -n ls-test -o json | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
rules=d['spec'].get('matchRules',[])
print('matchRules count:', len(rules) if rules else 0)
if rules:
    for rule in rules:
        ingress = rule.get('ingress',[])
        if any('model-api-test-regression' in str(r) for r in ingress):
            print(f'  configDisable={rule.get(\"configDisable\")}, ingress={ingress}')
"

# 2.8 数据面验证-无 key（禁用后应返回 200）
curl -s -o /dev/null -w '%{http_code}' 'http://8.156.87.83/api/v1/chat/completions' \
  -H 'Content-Type: application/json' \
  -H 'x-higress-llm-model: test-regression/qwen-plus' \
  -d '{"model":"qwen-plus","messages":[{"role":"user","content":"hi"}]}'
```

---

## US-MA-3：消费者授权

每个授权相关步骤需要同时验证：
- **管理面 API 响应**：接口返回 code=200
- **分片 ConfigMap 结构**：shard ConfigMap 的 matchRules 中包含 Model API 展开后的实际路由名（而非 modelApiId）
- **数据面行为**：client 实际请求 gateway，根据 HTTP status code 判断授权是否生效

| # | 场景 | 操作 | 管理面预期 | CR/ConfigMap 预期 | 数据面预期 |
|---|------|------|-----------|------------------|-----------|
| 3.1 | 授权消费者到 Model API | batchGrantModelApi | code=200 | — | — |
| 3.2 | 授权后分片 ConfigMap 验证 | 检查 shard ConfigMap | — | consumer 所在 shard 的 matchRules 包含 model-api 展开后的路由名（如 `model-api-test-regression-api-0-header-0`） | — |
| 3.3 | 查询授权消费者列表 | listModelApiConsumers | 包含已授权的 consumer | — | — |
| 3.4 | 数据面-已授权 consumer 请求 | 带正确 key 请求 | — | — | **200** |
| 3.5 | 数据面-未授权 consumer 请求 | 带其他 consumer 的 key 请求 | — | — | **403** |
| 3.6 | 数据面-无 key 请求 | 不带 key 请求 | — | — | **401** |
| 3.7 | 取消授权 | revokeModelApiGrant | code=200 | — | — |
| 3.8 | 取消后分片 ConfigMap 验证 | 检查 shard ConfigMap | — | 该 consumer 对应的 matchRules 条目已移除 | — |
| 3.9 | 取消后数据面验证 | 带原 key 请求 | — | — | **403** |

### 验证命令

```bash
# 3.1 授权消费者
curl -s 'http://47.109.143.5/api/gateway/modelapi/batchGrantModelApi' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{
    "gwInstanceId":"i-lci63hlysglgtpry1sjq",
    "modelApiId":"model-api-test-regression-api",
    "consumerIds":["consumer-ls.test"]
  }'

# 3.2 分片 ConfigMap 验证
# 计算 consumer-ls.test 的 shard index，然后检查对应 shard ConfigMap
SHARD_INDEX=$(python3 -c "
import hashlib, struct
name = 'consumer-ls.test'
# MurmurHash3_32 模拟（与 Java Guava Hashing.murmur3_32_fixed 一致）
import ctypes
h = ctypes.c_int32(hash(name)).value  # 简化，实际需要用 mmh3
print(abs(h) % 64)
")
kubectl get configmap hi-key-auth-shard-${SHARD_INDEX} -n ls-test -o yaml | \
  grep -A5 'model-api-test-regression'

# 或者直接搜索所有 shard 中是否包含该路由
for i in $(seq 0 63); do
  CM=$(kubectl get configmap hi-key-auth-shard-$i -n ls-test -o jsonpath='{.data.matchRules}' 2>/dev/null)
  if echo "$CM" | grep -q 'model-api-test-regression'; then
    echo "Found in shard-$i:"
    echo "$CM" | grep -B2 -A2 'model-api-test-regression'
    break
  fi
done

# 3.3 查询授权消费者列表
curl -s 'http://47.109.143.5/api/gateway/modelapi/listModelApiConsumers' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{
    "gwInstanceId":"i-lci63hlysglgtpry1sjq",
    "modelApiId":"model-api-test-regression-api",
    "current":1,"size":10
  }'

# 3.4 数据面-已授权（Bearer token，等待 ~15s ECDS 推送后）
curl -s -o /dev/null -w '%{http_code}' 'http://8.156.87.83/api/v1/chat/completions' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer g7ihtvme7e5liwpmd5ld' \
  -H 'x-higress-llm-model: test-regression/qwen-plus' \
  -d '{"model":"qwen-plus","messages":[{"role":"user","content":"hi"}]}'

# 3.5 数据面-未授权 consumer
curl -s -o /dev/null -w '%{http_code}' 'http://8.156.87.83/api/v1/chat/completions' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer some-unauthorized-key' \
  -H 'x-higress-llm-model: test-regression/qwen-plus' \
  -d '{"model":"qwen-plus","messages":[{"role":"user","content":"hi"}]}'

# 3.6 数据面-无 key
curl -s -o /dev/null -w '%{http_code}' 'http://8.156.87.83/api/v1/chat/completions' \
  -H 'Content-Type: application/json' \
  -H 'x-higress-llm-model: test-regression/qwen-plus' \
  -d '{"model":"qwen-plus","messages":[{"role":"user","content":"hi"}]}'

# 3.7 取消授权（需要先从 listModelApiConsumers 获取 authId）
curl -s 'http://47.109.143.5/api/gateway/modelapi/revokeModelApiGrant' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{
    "gwInstanceId":"i-lci63hlysglgtpry1sjq",
    "authId":"<从 listModelApiConsumers 获取>"
  }'

# 3.8 取消后分片 ConfigMap 验证
for i in $(seq 0 63); do
  CM=$(kubectl get configmap hi-key-auth-shard-$i -n ls-test -o jsonpath='{.data.matchRules}' 2>/dev/null)
  if echo "$CM" | grep -q 'model-api-test-regression'; then
    echo "Still found in shard-$i (should be removed):"
    echo "$CM" | grep -B2 -A2 'model-api-test-regression'
    break
  fi
done
echo "Not found in any shard (expected after revoke)"

# 3.9 取消后数据面验证（等待 ~15s ECDS 推送后）
curl -s -o /dev/null -w '%{http_code}' 'http://8.156.87.83/api/v1/chat/completions' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer g7ihtvme7e5liwpmd5ld' \
  -H 'x-higress-llm-model: test-regression/qwen-plus' \
  -d '{"model":"qwen-plus","messages":[{"role":"user","content":"hi"}]}'
```

---

## US-MA-4：路由级插件列表（本次修复验证）

| # | 场景 | 操作 | 预期结果 |
|---|------|------|----------|
| 4.1 | 普通路由查询 key-auth 插件 | listStrategyConfigs scope.routeId="ls-test2" | total=1，返回 key-auth（status=true） |
| 4.2 | Model API 路由查询（已启用认证） | listStrategyConfigs scope.routeId="model-api-xxx" | 返回对应插件（注：model API 路由可能走 CR 路径） |
| 4.3 | 无 key-auth 的路由查询 | listStrategyConfigs scope.routeId="some-route-without-auth" | total=0 |
| 4.4 | 不带 scope 查询所有 key-auth | listStrategyConfigs strategyName="key-auth" | 返回所有路由级 key-auth 实例（不含 model-api 前缀的） |

### 验证命令

```bash
# 4.1 普通路由（已验证通过）
curl -s 'http://47.109.143.5/api/gateway/strategyConfig/listStrategyConfigs' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{"scope":{"routeId":"ls-test2"},"gwInstanceId":"i-lci63hlysglgtpry1sjq"}'

# 4.4 不带 scope 查询所有
curl -s 'http://47.109.143.5/api/gateway/strategyConfig/listStrategyConfigs' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{"strategyName":"key-auth","gwInstanceId":"i-lci63hlysglgtpry1sjq","current":1,"size":10}'
```

---

## US-MA-5：Model API 路由列表

| # | 场景 | 操作 | 预期结果 |
|---|------|------|----------|
| 5.1 | 查询 Model API 关联路由 | POST /modelapi/listModelApiRoutes | 返回实际路由名列表 |

### 验证命令

```bash
curl -s 'http://47.109.143.5/api/gateway/modelapi/listModelApiRoutes' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{"gwInstanceId":"i-lci63hlysglgtpry1sjq","id":"model-api-test-regression-api"}'
```

---

## 执行顺序

### Round 1：2.1.11 非分片模式

> **前置准备**：由于只有一个测试实例（初始为 2.1.12），需要先降级到 2.1.11 来测试非分片路径。降级步骤见「版本切换命令」。

1. **Phase 0**: 降级数据面到 2.1.11（gateway 镜像 + controller 镜像 + 数据库版本号），确认 FeatureGate 不生效
2. **Phase 1**: US-MA-2 认证管理（启用/禁用，验证 CR matchRules 写入正确）
3. **Phase 2**: US-MA-3 消费者授权（验证 CR allow 列表正确，数据面生效）
4. **Phase 3**: US-MA-4 路由级插件列表（验证从 CR 查询正确）

### Round 2：升级到 2.1.12 分片模式（升级兼容性验证）

> **操作**：升级 gateway + controller 镜像到 2.1.12，修改数据库版本号为 2.1.12。升级后 Admin 会触发 fullPublish。

升级数据面到 2.1.12，验证：
- 升级后 Admin 触发 fullPublish，将 CR 中的配置迁移到分片 ConfigMap
- **Round 1 中创建的授权关系在升级后仍然可用**（数据面鉴权不中断）

1. **Phase 0**: 升级数据面到 2.1.12，等待 Admin 触发 fullPublish
2. **Phase 1**: 升级兼容性验证 — Round 1 的授权关系是否仍然生效（数据面验证）
3. **Phase 2**: US-MA-2 认证管理（启用/禁用，验证 route-switches 写入正确）
4. **Phase 3**: US-MA-3 消费者授权（验证 shard ConfigMap 写入正确，数据面生效）
5. **Phase 4**: US-MA-4 路由级插件列表（验证从 route-switches 构建正确）
6. **Phase 5**: US-MA-1 CRUD 基础操作
7. **Phase 6**: 清理测试数据

### 升级兼容性验证要点

升级到 2.1.12 后，Admin 会检测到版本变化并触发 `InstanceUpgradedEvent` → `fullPublish`：
- fullPublish 从 MySQL 读取所有 consumers 和 authorizations，重建分片 ConfigMap
- CR matchRules 被清空，resourceRefs 指向分片 ConfigMap
- **预期**：Round 1 中通过 CR 创建的授权关系已持久化到 MySQL，fullPublish 会将其迁移到分片 ConfigMap，数据面鉴权不中断

| # | 验证项 | 预期 |
|---|--------|------|
| U-1 | 升级后 fullPublish 是否触发 | Admin 日志可见 `[KeyAuthSharding] Starting full publish` |
| U-2 | Round 1 的 Model API 认证是否仍生效 | 无 key → 401，已授权 key → 200 |
| U-3 | Round 1 的 MCP Server 认证是否仍生效 | 无 key → 401，已授权 key → 200 |
| U-4 | route-switches ConfigMap 是否包含之前的路由 | kubectl 验证 |
| U-5 | shard ConfigMap 是否包含之前的授权关系 | kubectl 验证 |

### 版本切换命令

```bash
# 降级到 2.1.11（三步）

# Step 1: gateway 容器降级（只改 higress-gateway 容器，不动 nginx）
kubectl set image deployment/higress-gateway \
  higress-gateway=higress-registry.cn-hangzhou.cr.aliyuncs.com/higress/gateway:2.1.11 \
  -n ls-test

# Step 2: controller 容器降级
kubectl set image deployment/higress-controller \
  higress=higress-registry.cn-hangzhou.cr.aliyuncs.com/higress/higress:2.1.11 \
  -n ls-test

# Step 3: 修改数据库版本号（Admin 通过此字段判断分片模式，不会自动从 image tag 检测）
kubectl exec -it mysql-builtin-0 -n apigateway-system -- \
  mysql -u root -pAdmin123@ascm cop_gateway -e \
  "UPDATE gateway_instance SET higress_version='2.1.11' WHERE gw_instance_id='<gwInstanceId>';"

# 升级到 2.1.12（两步，版本号由 Admin upgrade 接口自动写入）

# Step 1: gateway 容器升级
kubectl set image deployment/higress-gateway \
  higress-gateway=registry.cn-shanghai.aliyuncs.com/daofeng/gateway:2.1.12 \
  -n ls-test

# Step 2: controller 容器升级
kubectl set image deployment/higress-controller \
  higress=registry.cn-shanghai.aliyuncs.com/daofeng/higress:2.1.12-amd64 \
  -n ls-test

# Step 3: 修改数据库版本号（模拟 upgrade 操作）
kubectl exec -it mysql-builtin-0 -n apigateway-system -- \
  mysql -u root -pAdmin123@ascm cop_gateway -e \
  "UPDATE gateway_instance SET higress_version='2.1.12' WHERE gw_instance_id='<gwInstanceId>';"

# 确认版本
kubectl get deployment higress-controller -n ls-test \
  -o jsonpath='{.spec.template.spec.containers[0].image}'
kubectl get deployment higress-gateway -n ls-test \
  -o jsonpath='{.spec.template.spec.containers[0].image}'
```

> **注意**：Admin 的 `InstanceFeatureChecker` 通过数据库中 `gateway_instance.higress_version` 字段判断是否走分片模式，不会自动从 K8s image tag 检测。降级时必须手动修改数据库，升级时由 Admin 的 upgrade 接口自动写入（测试环境手动模拟）。

---

## 注意事项

1. Model API 的路由发布是**异步**的（通过 Spring Event），创建/更新后需等待 ~5s 再验证数据面
2. `KeyAuthPluginHandler` 已修复：分片模式下通过 `keyAuthShardingPublisher.addOrUpdateRouteSwitch()` 写入 route-switches ConfigMap，与普通路由行为一致；非分片模式仍走 CR matchRules 路径
3. Model API 路由名以 `model-api-` 前缀开头，在 `listStrategyConfigs` 的非 scope 查询中会被 `isModelApiScope` 过滤器排除（这是设计行为）
4. 数据面 ECDS 推送延迟约 10-15 秒，配置变更后需等待
5. 非分片模式（2.1.11）下数据面通过 CR → Istio 直接推送，延迟更短（~5s）

---

## 验证方法论

每个认证相关的 US 必须通过**三层验证**才算通过：

| 层级 | 验证内容 | 工具 |
|------|---------|------|
| L1 管理面 | API 返回 code=200，业务字段正确 | curl → Admin API |
| L2 存储层 | WasmPlugin CR / route-switches / shard ConfigMap 结构符合分片预期 | kubectl get/describe |
| L3 数据面 | client 请求 gateway，HTTP status code 符合预期（200/401/403） | curl → Gateway |

### L2 验证要点（分片模式预期）

| 检查项 | 预期状态 |
|--------|---------|
| WasmPlugin CR `spec.matchRules` | **为空**（已迁移到分片 ConfigMap + route-switches） |
| WasmPlugin CR `spec.resourceRefs` | 包含 shard ConfigMap 名 + `hi-key-auth-route-switches` |
| WasmPlugin CR `spec.defaultConfig.consumers` | **为空**（已迁移到分片 ConfigMap） |
| route-switches ConfigMap | 所有路由（含普通路由和 Model API 路由）的 key-auth 开关 |
| shard ConfigMap `matchRules` | 按 consumer hash 分桶的授权关系（ingress=[routeName], config.allow=[consumer]） |

### L2 验证要点（非分片模式预期）

| 检查项 | 预期状态 |
|--------|---------|
| WasmPlugin CR `spec.matchRules` | 包含所有路由级 key-auth 配置（configDisable + ingress + allow） |
| WasmPlugin CR `spec.resourceRefs` | 为空或不存在 |
| route-switches ConfigMap | 不存在或为空 |
| shard ConfigMap | 不存在 |
