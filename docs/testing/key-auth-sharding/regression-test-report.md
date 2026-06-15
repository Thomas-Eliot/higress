# Key-Auth 分片 Model API & MCP Server 回归测试报告

**测试日期**: 2026-05-20  
**测试环境**: ls-test 实例 (i-v06q4pewoe26o1h5t9ww)  
**测试人员**: lvshui + AI Agent  
**Gateway IP**: 47.109.178.199  
**Admin IP**: 47.109.143.5  

---

## 1. 环境信息

| 项目 | 值 |
|------|------|
| 网关实例 ID | i-v06q4pewoe26o1h5t9ww |
| 数据面 Namespace | ls-test |
| 测试 Model API | model-api-test-regression-api |
| 测试 MCP Server | mock-publist-test |
| 测试 Consumer | regression-consumer (key: regression-test-key-001, BEARER) |
| Round 1 版本 | 2.1.11 (非分片) |
| Round 2 版本 | 2.1.12 (分片) |

---

## 2. Round 1：2.1.11 非分片模式

### US-MA-2：Model API 认证管理

| # | 场景 | L1 管理面 | L2 CR 结构 | L3 数据面 | 结果 |
|---|------|-----------|-----------|-----------|------|
| 2.1 | 启用认证 | ✅ code=200 | ✅ matchRules=1, ingress=[model-api-test-regression-api-0-header-0], configDisable=False | — | ✅ |
| 2.4 | 启用后-无 key | — | — | ✅ **401** | ✅ |
| 2.5 | 启用后-有效 key | — | — | ❌ **403** | ⚠️ 见发现 1 |
| 2.6 | 禁用认证 | ✅ code=200 | ✅ configDisable=True | — | ✅ |
| 2.8 | 禁用后-无 key | — | — | ✅ **503**（放行，后端不可用） | ✅ |
| 2.9 | 重新启用 | ✅ code=200 | ✅ configDisable=False | — | ✅ |
| 2.10 | 重新启用后-无 key | — | — | ✅ **401** | ✅ |

### US-MA-3：Model API 消费者授权

| # | 场景 | L1 管理面 | L2 CR 结构 | L3 数据面 | 结果 |
|---|------|-----------|-----------|-----------|------|
| 3.1 | 授权 consumer | ✅ code=200 | ⚠️ allow 写入了 modelApiId 而非实际路由名 | — | ⚠️ 见发现 1 |
| 3.4 | 已授权-有效 key | — | — | ❌ **403** | ⚠️ 见发现 1 |

### US-MCP-1：MCP Server 认证启用/禁用

| # | 场景 | L1 管理面 | L2 CR 结构 | L3 数据面 | 结果 |
|---|------|-----------|-----------|-----------|------|
| 1.2 | 启用 key-auth | ✅ code=200 | ✅ ingress=[mock-publist-test], configDisable=False | — | ✅ |
| 1.3 | 启用后-无 key | — | — | ✅ **401** | ✅ |
| 1.4 | 禁用 key-auth | ✅ code=200 | ✅ configDisable=True | — | ✅ |
| 1.5 | 禁用后-无 key | — | — | ✅ **200** | ✅ |
| 1.6 | 重新启用 | ✅ code=200 | ✅ configDisable=False | — | ✅ |
| 1.7 | 重新启用后-无 key | — | — | ✅ **401** | ✅ |

### US-MCP-2：MCP Server 消费者授权

| # | 场景 | L1 管理面 | L2 CR 结构 | L3 数据面 | 结果 |
|---|------|-----------|-----------|-----------|------|
| 2.1 | 授权 consumer | ✅ code=200 | ✅ allow=[regression-consumer] | — | ✅ |
| 2.4 | 已授权-有效 key | — | — | ✅ **200** (x-mse-consumer=regression-consumer) | ✅ |
| 2.5 | 未授权-无效 key | — | — | ✅ **401** | ✅ |
| 2.6 | 无 key | — | — | ✅ **401** | ✅ |

---

## 3. 版本升级（2.1.11 → 2.1.12）

### 升级步骤
1. gateway 镜像升级到 `daofeng/gateway:2.1.12`
2. controller 镜像升级到 `daofeng/higress:2.1.12-amd64`
3. 数据库 higress_version 修改为 `2.1.12`
4. 手动调用 `/application/fullPublish` 触发分片迁移

### fullPublish 结果
- 从 MySQL 加载 1 个 consumer、1 个 authorization
- 创建 1 个 active shard（shard-14）
- 清空 CR matchRules 和 defaultConfig.consumers
- 更新 resourceRefs 指向 shard-14

### 升级兼容性验证

| # | 验证项 | 预期 | 实际 | 结果 |
|---|--------|------|------|------|
| U-1 | fullPublish 触发 | 成功 | ✅ 手动触发成功 | ✅ |
| U-2 | Model API 认证仍生效 | 无 key → 401 | ✅ 401 | ✅ |
| U-3 | Model API 授权仍生效 | 有效 key → 200/503 | ✅ 503（后端不可用，key-auth 通过） | ✅ |
| U-4 | MCP Server 认证仍生效 | 无 key → 401 | ❌ 200（route-switches 丢失） | ❌ 见发现 2 |
| U-5 | MCP Server 授权仍生效 | 有效 key → 200 | ❌ 403（MySQL 无授权记录） | ❌ 见发现 3 |

---

## 4. Round 2：2.1.12 分片模式

### US-MCP-1：MCP Server 认证启用/禁用（重新创建后）

| # | 场景 | L1 管理面 | L2 route-switches | L3 数据面 | 结果 |
|---|------|-----------|-------------------|-----------|------|
| 1.2 | 创建 key-auth | ✅ code=200 | ✅ configDisable=false, ingress=[mock-publist-test] | — | ✅ |
| 1.3 | 启用后-无 key | — | — | ✅ **401** | ✅ |

### US-MCP-2：MCP Server 消费者授权（分片模式）

| # | 场景 | L1 管理面 | L2 shard ConfigMap | L3 数据面 | 结果 |
|---|------|-----------|-------------------|-----------|------|
| 2.1 | 授权 consumer | ✅ code=200 | ❌ shard 中无 mock-publist-test | ❌ **403** | ❌ 见发现 4 |

### US-MA-2/3：Model API（分片模式）

| # | 场景 | L3 数据面 | 结果 |
|---|------|-----------|------|
| 无 key | — | ✅ **401** | ✅ |
| 有效 key（已授权） | — | ✅ **503**（key-auth 通过） | ✅ |

---

## 5. 发现的问题

### 发现 1：非分片模式下 Model API 授权写入错误的路由名（P2）

**现象**：`batchGrantModelApi` 授权后，CR 中 allow 列表的 `_match_route_` 是 `model-api-test-regression-api`（modelApiId），而不是实际路由名 `model-api-test-regression-api-0-header-0`。

**根因**：`KeyAuthPublishEventListener.updateAllowListForConsumer()` 直接使用 `grantTargetId`（即 modelApiId）作为路由名写入 CR，没有像分片模式的 `resolveMatchRuleEntries()` 那样展开为实际路由名。

**影响**：非分片模式下 Model API 的消费者授权在数据面不生效（key-auth 按实际路由名匹配，找不到 modelApiId）。

**修复建议**：`updateAllowListForConsumer` 中对 MODEL_API 类型的 grantTargetId 增加路由名展开逻辑。

---

### 发现 2：升级后 route-switches 丢失（P0 - 升级兼容性）

**现象**：从 2.1.11 升级到 2.1.12 后，fullPublish 清空了 CR matchRules，但没有将其中的路由级 key-auth 开关迁移到 route-switches ConfigMap。

**根因**：`KeyAuthShardingPublisher.fullPublish()` 只处理 authorization（从 MySQL 读取授权关系写入 shard ConfigMap），不处理路由级 key-auth 开关（route-switches）。升级前 CR matchRules 中的 `configDisable` 信息在 fullPublish 时被清空，没有迁移。

**影响**：升级后所有路由的 key-auth 开关丢失，需要用户手动重新启用。

**修复建议**：`fullPublish` 在清空 CR matchRules 前，先将其中的路由级 key-auth 开关信息迁移到 route-switches ConfigMap。

---

### 发现 3：非分片模式下 MCP Server 授权不写 MySQL（P1 - 升级兼容性）

**现象**：在 2.1.11 非分片模式下通过 `addMcpServerConsumers` 创建的授权关系，升级到 2.1.12 后丢失。

**根因**：`McpServerAdapter.addConsumers()` 在非分片模式下直接调用 `mcpServerService.addAllowConsumers()` 写 CR，不经过 MySQL 持久化。升级后 fullPublish 从 MySQL 读取授权关系，找不到 MCP Server 的授权记录。

**影响**：升级后 MCP Server 的消费者授权丢失，需要用户重新授权。

**修复建议**：
- 方案 A：非分片模式下 `addMcpServerConsumers` 也写入 MySQL（与 `batchGrantModelApi` 一致）
- 方案 B：`fullPublish` 在迁移前先从 CR matchRules 中提取现有授权关系写入 MySQL

---

### 发现 4：分片模式下 MCP Server 授权不写 MySQL（P0 - 功能 Bug）

**现象**：在 2.1.12 分片模式下通过 `addMcpServerConsumers` 授权后，shard ConfigMap 中没有 MCP Server 路由的授权。

**根因**：`McpServerAdapter.addConsumers()` 在分片模式下直接调用 `keyAuthShardingPublisher.publishAuthorization(gwInstanceId, consumer)`，但没有先将授权关系写入 MySQL。`publishAuthorization` 内部调用 `rebuildShard`，从 MySQL 读取该 consumer 的所有授权关系来重建 shard。由于 MySQL 中没有 MCP Server 的授权记录，重建后的 shard 不包含 MCP Server 路由。

**影响**：分片模式下 MCP Server 的消费者授权完全不生效。

**修复建议**：`McpServerAdapter.addConsumers()` 在调用 `publishAuthorization` 前，先将授权关系写入 MySQL（参考 `HigressAuthorizationServiceImpl.createAppAuth` 的流程）。

---

## 6. 测试结论

| 维度 | 结果 | 说明 |
|------|------|------|
| Model API 认证启用/禁用 | ✅ 通过 | 两个版本均正常 |
| Model API 消费者授权（分片模式） | ✅ 通过 | shard ConfigMap 正确展开路由名 |
| Model API 消费者授权（非分片模式） | ❌ 失败 | 路由名未展开（发现 1） |
| MCP Server 认证启用/禁用 | ✅ 通过 | 两个版本均正常 |
| MCP Server 消费者授权（非分片模式） | ✅ 通过 | CR allow 列表正确 |
| MCP Server 消费者授权（分片模式） | ❌ 失败 | 不写 MySQL 导致 shard 为空（发现 4） |
| 升级兼容性 - Model API | ✅ 通过 | 授权关系从 MySQL 正确迁移到 shard |
| 升级兼容性 - MCP Server 认证 | ❌ 失败 | route-switches 丢失（发现 2） |
| 升级兼容性 - MCP Server 授权 | ❌ 失败 | MySQL 无记录导致迁移失败（发现 3） |

### 优先级排序

| 优先级 | 问题 | 影响范围 |
|--------|------|---------|
| **P0** | 发现 4：分片模式下 MCP Server 授权不写 MySQL | 2.1.12 新功能完全不可用 |
| **P0** | 发现 2：升级后 route-switches 丢失 | 升级后所有路由 key-auth 开关丢失 |
| **P1** | 发现 3：非分片模式下 MCP Server 授权不写 MySQL | 升级后 MCP 授权丢失 |
| **P2** | 发现 1：非分片模式下 Model API 授权路由名错误 | 非分片模式下 Model API 授权不生效 |

---

## 7. 修复状态

| 优先级 | 问题 | 修复 commit | 状态 |
|--------|------|-------------|------|
| **P0** | 发现 4：分片模式下 MCP Server 授权不写 MySQL | e7aaa6233 | ✅ 已修复 |
| **P0** | 发现 2：升级后 route-switches 丢失 | e7aaa6233 | ✅ 已修复 |
| **P1** | 发现 3：非分片模式下 MCP Server 授权不写 MySQL | e7aaa6233 | ✅ 已修复 |
| **P2** | 发现 1：非分片模式下 Model API 授权路由名错误 | — | 🔶 待修复（需评估） |

### commit e7aaa6233 修复内容

**McpServerAdapter.addConsumers**：重写为统一通过 `HigressAuthorizationServiceImpl.createAppAuth` 写入 MySQL 授权关系。`createAppAuth` 内部发布 `ConsumerPublishEvent`，自动触发分片模式的 `publishAuthorization` 或非分片模式的 `updateAllowListForConsumer`。非分片模式下额外走 CR 路径确保即时生效。

**McpServerAdapter.deleteConsumers**：统一通过 `HigressAuthorizationServiceImpl.deleteApplicationAuth` 从 MySQL 删除授权关系并触发事件。

**KeyAuthShardingPublisher.fullPublish**：新增 `migrateRouteSwitchesFromCR` 步骤，在清空 CR matchRules 前提取路由级 key-auth 开关信息迁移到 route-switches ConfigMap。

---

## 8. 待回归验证

修复代码已提交（commit e7aaa6233），需要重新部署 Admin 后回归验证：

1. 分片模式下 `addMcpServerConsumers` → shard ConfigMap 包含 MCP 路由 → 数据面 200
2. 非分片模式下 `addMcpServerConsumers` → MySQL 有记录 + CR allow 正确
3. 升级后 fullPublish → route-switches 包含之前的路由开关 → 数据面 401
4. 升级后 fullPublish → shard 包含 MCP Server 授权（因为 MySQL 有记录了）
