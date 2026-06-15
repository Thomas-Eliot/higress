# key-auth 分片改造 - 任务进度跟踪

## 已完成 ✅

### 核心功能
- [x] MySQL 持久化层（消费者 + 授权关系表）
- [x] 异步事件驱动发布（ConsumerPublishEvent + KeyAuthPublishEventListener）
- [x] publish_status 字段（PENDING / PUBLISHED / FAILED）
- [x] 分片 ConfigMap 写入（64 桶 MurmurHash，KeyAuthShardingPublisher）
- [x] Higress Controller 模板渲染（consumers 追加 + matchRules 合并）
- [x] 端到端鉴权验证通过
- [x] CRD 字段定义（4 个文件：wasmplugin.proto + pb.go + 2 个 gen.yaml）
- [x] 正式镜像构建 daofeng/higress:2.1.11-sharding
- [x] 全量发布触发入口：启动时自动 fullPublish（ConfigMapDataMigrator → fullPublishAll）
- [x] 全量发布触发入口：手动 API `POST /application/fullPublish`
- [x] 全量发布后批量更新 publish_status = PUBLISHED

### 分支
- harmony-gateway-admin → `feat/consumer-mysql-migration`
- higress → `feat/key-auth-config-sharding`
- higress-console → `feat/key-auth-config-sharding`

---

## 待办 🔲

### 2. 验证 helm upgrade CRD 更新流程
- [x] 在 csb2-helm (apsara-1.7xR) 的 WasmPlugin CRD 中添加 resourceRefs + resourceTemplateSchema 字段
  - `higress-broker/crds/customresourcedefinitions.gen.yaml`
  - `cloud-native-gateway/crds/customresourcedefinitions.gen.yaml`
- [x] 确认 kubectl apply CRD 能正确应用新增字段（ls-test 验证通过）
- [x] 验证已有 WasmPlugin CR 不受影响（10 个 CR 全部正常，向后兼容）

### 3. 压测 8K consumer
- [x] 准备 8K consumer 测试数据（实际测试 18000+）
- [x] 验证分片写入性能：fullPublish 64 个 ConfigMap 耗时 10.5s（18000 consumer）
- [x] 验证 xDS 生效延迟：创建 consumer → Envoy 鉴权生效 ≈ 3s
- [x] 验证单个分片不超过 200KB：最大 47.5KB，平均 41.7KB（18000 consumer）

### 4. 前端 publish_status 展示 + 重试按钮
- [x] 后端 AppResponse 增加 publishStatus 字段
- [x] HigressApp SDK 模型增加 publishStatus 字段
- [x] HigressConsumerDAO.toHigressApp() 映射 publishStatus
- [x] HigressApplicationQueryServiceImpl.convertToAppResponse() 映射 publishStatus
- [x] 前端 API 增加 retryPublish / fullPublish 方法
- [x] 消费者列表页增加「发布状态」列（待生效/已生效/生效失败，仅 Higress）
- [x] 状态标签样式（PENDING=warning, PUBLISHED=success, FAILED=danger）
- [x] 「重试发布」操作按钮（FAILED/PENDING 时显示）
- [x] 「全量发布」按钮（实例级别，带确认弹窗）

### 5. 清理废弃代码（暂缓，迁移完成后再清理）
- [ ] 删除 `ConfigMapAppAdapter`（迁移器仍在使用，保留）
- [ ] 删除 `ConfigMapAuthorizationAdapter`（迁移器仍在使用，保留）
- [x] 删除 `HigressApplicationPublisher`（已无调用方）
- [x] 删除 `HigressAuthorizationPublisher`（ModelApiPublisher 已改为事件驱动）
- [ ] 清理 WasmPlugin CR 中残留的 defaultConfig.consumers 和 matchRules

---

## 后续优化（非阻塞）
- [ ] 动态扩容：单个分片超过 200KB 时自动扩展桶数
- [ ] MCP Server 配置分片复用同一机制
- [ ] proto field number 与上游 Higress 沟通预留（当前用 104/105）
- [ ] ConfigMap watch debounce（防止短时间内多次变更导致 xDS push 风暴）

---

## 下一迭代：matchRules 分片重构

### 问题
当前 matchRules 按 consumer 分片，导致：
1. 同一个 route 的 `configDisable` 分散在多个分片中，修改开关需要改多个 ConfigMap
2. Controller 合并时 configDisable 冲突无法解决
3. 前端查询路由插件列表依赖 CR matchRules，清空后无法展示

### 最终方案

**数据分层：**
- **WasmPlugin CR matchRules**：只存路由开关（`{ingress: [route-X], configDisable: true/false, config: {allow: []}}`）
  - 作为 configDisable 的 source of truth
  - 前端查询路由插件列表从这里读
  - 路由数上限 5000，CR 大小约 150KB，不会超限
- **分片 ConfigMap consumers**：按 consumer hash 分片（当前方案不变）
- **分片 ConfigMap matchRules**：按 consumer hash 分片，只存 allow 数据，不写 configDisable
  - 每个分片中一个 route 的 allow 列表只包含该分片内的 consumer（约 625 个）
  - Controller 合并时按 ingress 聚合 allow 列表

**Controller 合并逻辑调整：**
1. 读取 CR matchRules 获取每个 route 的 configDisable 状态
2. 从分片 ConfigMap 聚合 matchRules 的 allow 列表（按 ingress 合并）
3. 如果 CR 中某 route 标记 `configDisable: true`，则忽略该 route 的 allow 列表

**改动范围：**

| 组件 | 改动 |
|------|------|
| admin - KeyAuthShardingPublisher | `updateWasmPluginResourceRefs` 不清理 matchRules，只清理有非空 allow 的 matchRules 中的 allow 数据（保留开关） |
| admin - KeyAuthShardingPublisher | 分片 ConfigMap matchRules 中不写 configDisable |
| admin - HigressStrategyInstanceAdapter | 创建/删除路由插件时写 CR matchRules（开关），同时触发分片更新 |
| admin - HigressApplicationServiceImpl | 路由数上限检查（5000） |
| Controller (Go) | 合并 matchRules 时：CR configDisable 优先，分片 allow 聚合 |

**约束：**
- 单实例 consumer 上限：50000
- 单实例路由上限：5000（key-auth 启用的路由）

---

## 回归测试 Bug 修复（2026-05-18）

### BUG-1 (P0): fullPublish 后 WasmPlugin CR resourceRefs 丢失 ✅ 已修复

**现象**: `fullPublish` API 返回 200，ConfigMap 分片数据正确写入，但 WasmPlugin CR 的 `resourceRefs` 为空，导致 Controller 无法读取分片数据，所有 consumer 鉴权失效。

**根因（双重问题）**:
1. `updateWasmPluginResourceRefs` 方法在 `replaceWasmPlugin` 失败时（如 409 Conflict）静默吞掉异常，`fullPublish` 返回 200 但 resourceRefs 实际未写入
2. `higress-system` 中的旧版 Controller（2.1.11，不含 resourceRefs 字段）定期通过 okhttp 覆盖 CRD，导致 CRD schema 中 resourceRefs 字段定义被删除，K8s 存储 CR 时静默丢弃该字段

**修复**:
- [x] `KeyAuthShardingPublisher.updateWasmPluginResourceRefs`: 增加 409 Conflict 重试（最多 3 次，指数退避），失败后抛 `BusinessException` 而非静默吞掉
- [x] `KeyAuthShardingPublisher.ensureResourceRefsConsistency`: 新增公共方法，检测"分片 ConfigMap 存在但 resourceRefs 缺失"的不一致状态并修复
- [x] `HigressStrategyInstanceAdapter.create/update`: 非分片模式下操作 key-auth 路由级配置后，调用 `ensureResourceRefsConsistency` 修复可能丢失的 resourceRefs
- [x] 升级 `higress-system` Controller 镜像到 `2.1.11-sharding`（包含 resourceRefs CRD 字段），阻止旧版本覆盖 CRD

**验证**: fullPublish 后 resourceRefs=65（64 shard + 1 route-switches），Controller ECDS 推送 3.1MB，数据面鉴权正确（无key→401，正确key→200）

### BUG-2 (P2): deleteStrategyConfig 在 CR 状态不一致时报 500 ✅ 已修复

**现象**: 多次创建/删除后调用 delete 返回 500 `没有找到对应的插件配置实例.实例id={0}`

**根因**: `WasmPluginInstanceServiceImpl.delete` 在 `queryService.getResource` 返回 null 时直接抛异常，不支持幂等

**修复**:
- [x] `WasmPluginInstanceServiceImpl.delete`: 当 strategyConfig == null 时 log.warn 并直接返回（幂等处理）
- [x] `HigressStrategyInstanceAdapter.delete`: 非分片模式下 `service.delete()` 失败时，对 key-auth 非全局 scope 做幂等处理

**验证**: 删除不存在的策略配置返回 200

### BUG-3 (P3): modifyStrategyConfigStatus 禁用机制与 ConfigMap 不一致 ✅ 根因已修复

**现象**: 禁用策略后 route-switches ConfigMap 中 `configDisable` 仍为 false

**根因**: BUG-1 的连锁反应。resourceRefs 缺失 → Controller 无法读取 ConfigMap → 禁用/启用虽然正确写入了 route-switches ConfigMap 的 configDisable，但 Controller 看不到

**修复**: BUG-1 修复后，Controller 能正确读取 route-switches ConfigMap 中的 configDisable 字段

---

## 验收审视发现的改进项

### P0 - 必须修复

- [ ] **publish_status 初始值为 NULL**：创建 consumer 时 `HigressConsumerDAO.toEntity()` 没有设置 `publishStatus = "PENDING"`，前端显示"未知"而非"待生效"
- [ ] **增量发布失败无重试机制**：`@Async` 事件处理失败后只标记 FAILED，没有自动重试。建议加 Spring Retry（最多 3 次，指数退避）

### P1 - 建议改进

- [x] **rebuildShard 全量读取再过滤**：DB 新增 `shard_index` 字段（创建时计算），查询时 `WHERE shard_index = ?` 直接过滤
- [ ] **并发安全：同 shard 并发 rebuild**：利用 K8s ConfigMap 的 resourceVersion 乐观锁，`replaceConfigMap` 遇到 409 Conflict 时重试即可，无需 Java 侧加锁
- [x] **前端"全量发布"按钮定位调整**：已去掉前端按钮，仅保留 `POST /application/fullPublish` API 给运维黑屏调用 ✅
- [x] **消费者列表内存分页**：改为 MySQL 分页（MyBatis-Plus `page()` + `LIMIT/OFFSET`）
- [ ] **路由插件列表支持分片模式**：当 WasmPlugin 有 `resourceRefs` 时，`StrategyInstanceQueryServiceImpl.pageResource` 需从分片 ConfigMap 聚合 matchRules 构建插件实例列表（当前 CR matchRules 被清空后前端显示空）

### P2 - 可优化

- [ ] **checkKeyIsExist 全量查询**：每次创建 consumer 都加载全量列表检查 key 重复。建议加 `credential_key + gw_instance_id` 唯一索引
- [ ] **压测 TPS 偏低（~14）**：每条 consumer 都触发增量发布写 K8s API。批量创建场景建议先写 MySQL 最后统一 fullPublish
