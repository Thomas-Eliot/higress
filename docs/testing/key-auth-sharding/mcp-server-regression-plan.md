# MCP Server 回归测试计划（Key-Auth 分片模式）

**版本**: key-auth-config-sharding  
**测试环境**: ls-test 实例  
**前置条件**: Key-Auth 分片功能已部署（FeatureGate KEY_AUTH_SHARDING >= 2.1.12）  
**关联修复**: commit 0f91e2e9d（MCP server addConsumers/deleteConsumers 分片模式下走 sharding 路径）

---

## 测试目标

验证 Key-Auth 分片模式下，MCP Server 的认证启用/禁用、消费者授权等功能正确生效。

重点关注：
1. MCP Server 路由的 key-auth 开关是否正确写入 route-switches ConfigMap
2. MCP Server 消费者授权是否正确写入分片 ConfigMap（而非 CR matchRules）
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
| 启用认证（handlerConsumerAuth） | key-auth 写入 CR matchRules | key-auth 写入 route-switches ConfigMap |
| 消费者授权（addMcpServerConsumers） | allow 列表写入 CR matchRules | 触发 shard ConfigMap 重建 |
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
| 测试用 MCP Server | 需新建或从 listMcpServers 确认已有的 |
| 测试用 Consumer | 需新建或确认已有 |
| Session Cookie | csb-sessionId-GATEWAY=70305c24-adbf-4661-a847-85660c14d159:68230d21-a596-4989-8edf-c925a5a091a1 |

> **重要**：当前环境已降级到 2.1.11（数据库 + 镜像），处于 Round 1 起始状态。

---

## US-MCP-1：MCP Server 认证启用/禁用

MCP Server 的 key-auth 启用/禁用走 `handlerConsumerAuth` → `HigressStrategyInstanceAdapter.create/enable/disable` → 分片模式写 route-switches。

| # | 场景 | 操作 | L1 管理面 | L2 CR/ConfigMap | L3 数据面 |
|---|------|------|-----------|-----------------|-----------|
| 1.1 | 查询已有 MCP Server | listMcpServers | 返回列表 | — | — |
| 1.2 | 启用 key-auth | handlerConsumerAuth (isOpen=true, name=mcpServerName) | code=200, 返回 strategyConfigId | route-switches 包含 MCP 路由名, configDisable=false | — |
| 1.3 | 启用后数据面-无 key | 请求 MCP Server SSE 端点 | — | — | **401** |
| 1.4 | 禁用 key-auth | handlerConsumerAuth (isOpen=false, strategyConfigId=xxx) | code=200 | route-switches 中 configDisable=true | — |
| 1.5 | 禁用后数据面-无 key | 请求 MCP Server SSE 端点 | — | — | **200**（放行） |
| 1.6 | 重新启用 | handlerConsumerAuth (isOpen=true, strategyConfigId=xxx) | code=200 | configDisable=false | — |
| 1.7 | 重新启用后数据面-无 key | 请求 MCP Server SSE 端点 | — | — | **401** |

### 验证命令

```bash
# 1.1 查询 MCP Server 列表
curl -s 'http://47.109.143.5/api/gateway/mcpServer/listMcpServers' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{"gwInstanceId":"i-v06q4pewoe26o1h5t9ww","current":1,"size":10}'

# 1.2 启用 key-auth（首次创建，不传 strategyConfigId）
curl -s 'http://47.109.143.5/api/gateway/strategyConfig/handlerConsumerAuth' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{
    "gwInstanceId":"i-v06q4pewoe26o1h5t9ww",
    "name":"<mcpServerName>",
    "isOpen":true
  }'

# 1.2 L2 验证 - route-switches ConfigMap
kubectl get configmap hi-key-auth-route-switches -n ls-test -o yaml | grep -A3 '<mcpServerName>'

# 1.3 数据面验证-无 key（MCP Server 路由名 = mcpServerName）
curl -s -o /dev/null -w '%{http_code}' 'http://8.156.87.83/<mcpServerPath>' \
  -H 'Content-Type: application/json'

# 1.4 禁用 key-auth
curl -s 'http://47.109.143.5/api/gateway/strategyConfig/handlerConsumerAuth' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{
    "gwInstanceId":"i-v06q4pewoe26o1h5t9ww",
    "strategyConfigId":"<从1.2返回的id>",
    "isOpen":false
  }'

# 1.5 禁用后数据面验证
curl -s -o /dev/null -w '%{http_code}' 'http://8.156.87.83/<mcpServerPath>' \
  -H 'Content-Type: application/json'
```

---

## US-MCP-2：MCP Server 消费者授权（本次修复重点）

MCP Server 的消费者授权走 `addMcpServerConsumers` → `McpServerAdapter.addConsumers`。  
修复前：直接写 CR matchRules（分片模式下不生效）  
修复后：分片模式下走 `KeyAuthShardingPublisher.publishAuthorization()` 重建 shard ConfigMap

| # | 场景 | 操作 | L1 管理面 | L2 CR/ConfigMap | L3 数据面 |
|---|------|------|-----------|-----------------|-----------|
| 2.1 | 授权消费者 | addMcpServerConsumers | code=200 | — | — |
| 2.2 | 授权后分片 ConfigMap 验证 | 检查 shard ConfigMap | — | consumer 所在 shard 的 matchRules 包含 MCP 路由名 | — |
| 2.3 | 查询授权消费者列表 | listMcpServerConsumers | 包含已授权 consumer | — | — |
| 2.4 | 数据面-已授权 consumer | 带正确 key 请求 | — | — | **200** |
| 2.5 | 数据面-未授权 consumer | 带其他 key 请求 | — | — | **403** |
| 2.6 | 数据面-无 key | 不带 key 请求 | — | — | **401** |
| 2.7 | 取消授权 | deleteMcpServerConsumers | code=200 | — | — |
| 2.8 | 取消后分片 ConfigMap 验证 | 检查 shard ConfigMap | — | 该 consumer 对应的 matchRules 条目已移除 | — |
| 2.9 | 取消后数据面验证 | 带原 key 请求 | — | — | **403** |

### 验证命令

```bash
# 2.1 授权消费者到 MCP Server
curl -s 'http://47.109.143.5/api/gateway/mcpServer/addMcpServerConsumers' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{
    "gwInstanceId":"i-v06q4pewoe26o1h5t9ww",
    "mcpServerName":"<mcpServerName>",
    "consumers":["consumer-ls.test"]
  }'

# 2.2 分片 ConfigMap 验证（搜索所有 shard）
for i in $(seq 0 63); do
  CM=$(kubectl get configmap hi-key-auth-shard-$i -n ls-test -o jsonpath='{.data.matchRules}' 2>/dev/null)
  if echo "$CM" | grep -q '<mcpServerName>'; then
    echo "Found in shard-$i:"
    echo "$CM" | grep -B2 -A2 '<mcpServerName>'
    break
  fi
done

# 2.3 查询授权消费者列表
curl -s 'http://47.109.143.5/api/gateway/mcpServer/listMcpServerConsumers' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{
    "gwInstanceId":"i-v06q4pewoe26o1h5t9ww",
    "mcpServerName":"<mcpServerName>",
    "current":1,"size":10
  }'

# 2.4 数据面-已授权 consumer（等待 ~15s ECDS 推送）
curl -s -o /dev/null -w '%{http_code}' 'http://8.156.87.83/<mcpServerPath>' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer g7ihtvme7e5liwpmd5ld'

# 2.5 数据面-未授权 consumer
curl -s -o /dev/null -w '%{http_code}' 'http://8.156.87.83/<mcpServerPath>' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer some-unauthorized-key'

# 2.6 数据面-无 key
curl -s -o /dev/null -w '%{http_code}' 'http://8.156.87.83/<mcpServerPath>' \
  -H 'Content-Type: application/json'

# 2.7 取消授权
curl -s 'http://47.109.143.5/api/gateway/mcpServer/deleteMcpServerConsumers' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{
    "gwInstanceId":"i-v06q4pewoe26o1h5t9ww",
    "mcpServerName":"<mcpServerName>",
    "consumers":["consumer-ls.test"]
  }'

# 2.8 取消后分片验证
for i in $(seq 0 63); do
  CM=$(kubectl get configmap hi-key-auth-shard-$i -n ls-test -o jsonpath='{.data.matchRules}' 2>/dev/null)
  if echo "$CM" | grep -q '<mcpServerName>'; then
    echo "Still found in shard-$i (should be removed):"
    echo "$CM" | grep -B2 -A2 '<mcpServerName>'
    break
  fi
done
echo "Not found in any shard (expected after revoke)"

# 2.9 取消后数据面验证（等待 ~15s）
curl -s -o /dev/null -w '%{http_code}' 'http://8.156.87.83/<mcpServerPath>' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer g7ihtvme7e5liwpmd5ld'
```

---

## US-MCP-3：路由级插件列表查询

| # | 场景 | 操作 | 预期结果 |
|---|------|------|----------|
| 3.1 | listStrategyConfigs scope=MCP 路由 | listStrategyConfigs scope.routeId=mcpServerName | 返回 key-auth（如果已启用） |

### 验证命令

```bash
curl -s 'http://47.109.143.5/api/gateway/strategyConfig/listStrategyConfigs' \
  -H 'Content-Type: application/json' \
  -b 'csb-sessionId-GATEWAY=<session>' \
  --data-raw '{"scope":{"routeId":"<mcpServerName>"},"gwInstanceId":"i-v06q4pewoe26o1h5t9ww"}'
```

---

## 执行顺序

### Round 1：2.1.11 非分片模式

> **前置准备**：由于只有一个测试实例（初始为 2.1.12），需要先降级到 2.1.11 来测试非分片路径。降级步骤见「版本切换命令」。

1. **Phase 0**: 降级数据面到 2.1.11（gateway 镜像 + controller 镜像 + 数据库版本号），确认 FeatureGate 不生效
2. **Phase 1**: US-MCP-1 认证启用/禁用（验证 CR matchRules 写入正确，数据面生效）
3. **Phase 2**: US-MCP-2 消费者授权（验证 CR allow 列表正确写入，数据面生效）
4. **Phase 3**: US-MCP-3 路由级插件列表（验证从 CR 查询正确）

### Round 2：升级到 2.1.12 分片模式（升级兼容性验证）

> **操作**：升级 gateway + controller 镜像到 2.1.12，修改数据库版本号为 2.1.12。升级后 Admin 会触发 fullPublish。

升级数据面到 2.1.12，验证：
- 升级后 Admin 触发 fullPublish，将 CR 中的配置迁移到分片 ConfigMap
- **Round 1 中创建的授权关系在升级后仍然可用**（数据面鉴权不中断）

1. **Phase 0**: 升级数据面到 2.1.12，等待 Admin 触发 fullPublish
2. **Phase 1**: 升级兼容性验证 — Round 1 的授权关系是否仍然生效（数据面验证）
3. **Phase 2**: US-MCP-1 认证启用/禁用（验证 route-switches 写入正确）
4. **Phase 3**: US-MCP-2 消费者授权（验证 shard ConfigMap 写入正确，数据面生效）
5. **Phase 4**: US-MCP-3 路由级插件列表（验证从 route-switches 构建正确）

### 升级兼容性验证要点

升级到 2.1.12 后，Admin 会检测到版本变化并触发 `InstanceUpgradedEvent` → `fullPublish`：
- fullPublish 从 MySQL 读取所有 consumers 和 authorizations，重建分片 ConfigMap
- CR matchRules 被清空，resourceRefs 指向分片 ConfigMap
- **预期**：Round 1 中通过 CR 创建的授权关系已持久化到 MySQL，fullPublish 会将其迁移到分片 ConfigMap，数据面鉴权不中断

| # | 验证项 | 预期 |
|---|--------|------|
| U-1 | 升级后 fullPublish 是否触发 | Admin 日志可见 `[KeyAuthSharding] Starting full publish` |
| U-2 | Round 1 的 MCP Server 认证是否仍生效 | 无 key → 401，已授权 key → 200 |
| U-3 | route-switches ConfigMap 是否包含之前的路由 | kubectl 验证 |
| U-4 | shard ConfigMap 是否包含之前的授权关系 | kubectl 验证 |

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

## 验证方法论（同 Model API）

| 层级 | 验证内容 | 工具 |
|------|---------|------|
| L1 管理面 | API 返回 code=200，业务字段正确 | curl → Admin API |
| L2 存储层 | route-switches / shard ConfigMap 结构符合分片预期 | kubectl |
| L3 数据面 | client 请求 gateway，HTTP status code 符合预期 | curl → Gateway |

---

## 注意事项

1. MCP Server 路由名 = `mcpServerName`（由 `McpServerHelper.mcpServerName2RouteName` 转换，通常就是 MCP Server 的 name）
2. MCP Server 的 key-auth 启用走 `handlerConsumerAuth` → `HigressStrategyInstanceAdapter`，分片模式下写 route-switches，非分片模式写 CR matchRules
3. MCP Server 的消费者授权走 `addMcpServerConsumers` → `McpServerAdapter.addConsumers`，已修复：分片模式走 `KeyAuthShardingPublisher.publishAuthorization()`，非分片模式走 higress-sdk `AuthorizationOfKeyAuthServiceImpl.bindList()` 写 CR
4. `publishAuthorization` 会从 MySQL 重建该 consumer 所在 shard 的 ConfigMap，前提是授权关系已写入 MySQL
5. 数据面 ECDS 推送延迟约 10-15 秒（分片模式），CR 推送延迟约 5 秒（非分片模式）
6. **MCP Server 的 `addMcpServerConsumers` 在非分片模式下直接写 CR allow 列表，不经过 MySQL 持久化授权关系**。升级到分片模式后，fullPublish 从 MySQL 读取授权关系——如果授权关系没有写入 MySQL，升级后会丢失。需要确认 MCP Server 授权是否也写了 MySQL。
