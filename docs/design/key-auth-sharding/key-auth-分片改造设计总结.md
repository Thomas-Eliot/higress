# key-auth 插件配置分片改造 - 设计总结

## 1. 背景与问题

WasmPlugin CR（key-auth.internal）将所有消费者凭证和授权关系存储在单个 K8s 资源中。当消费者数量达到 8K+ 时，CR 大小超过 etcd 1.5MB 存储限制，导致配置无法写入。

同时，原有的持久化层使用 ConfigMap（每个消费者一个 `hi-app-key-*`，每条授权一个 `hi-authorization-*`），在 10W 消费者场景下会产生 20W+ ConfigMap，对 K8s API Server 造成巨大压力。

## 2. 核心决策

### 2.1 持久化层：ConfigMap → MySQL

**决策**：将消费者和授权关系的持久化存储从 ConfigMap 迁移到 MySQL。

**理由**：
- ConfigMap 一个资源一个，10W 消费者 = 10W ConfigMap，API Server 不堪重负
- MySQL 支持高效的分页查询、条件过滤，适合大规模数据管理
- 项目已有 MySQL 基础设施（MariaDB + MyBatis-Plus）

**迁移策略**：
- 启动时自动迁移：从 ConfigMap + WasmPlugin CR 两个数据源读取，合并写入 MySQL
- 迁移成功一条即删除对应 ConfigMap（避免下次无效同步）
- 幂等设计：唯一键冲突跳过，多实例并发启动安全

### 2.2 运行时配置：单 CR → 分片 ConfigMap + 模板渲染

**决策**：将 WasmPlugin CR 的 consumers 和 matchRules 拆分到多个 ConfigMap 中，由 Higress Controller 在生成 xDS 配置时合并渲染。

**理由**：
- 单个 WasmPlugin CR 有 etcd 1.5MB 限制
- 分片 ConfigMap 每个限制 200KB，可以支撑大规模消费者
- Istio/Higress Controller 已有 ConfigMap watch 机制，扩展成本低

### 2.3 分片策略：Hash 分片

**决策**：按 consumer name 的 MurmurHash（Guava）取模，固定 64 个桶。

**理由**：
- Hash 分片总量可控，分布均匀（验证：8000 consumer，min=90/桶，max=146/桶，std=10.2）
- 固定桶数避免 reHash 复杂度
- 64 桶 × 4W consumer / 64 = 625/桶 × 200B ≈ 125KB/桶，在 200KB 限制内

**为什么不用递增 ID 分片**：批量删除重建会导致 ConfigMap 数量不可控。

### 2.4 分片范围：consumers + matchRules 都分片

**决策**：consumers 和 matchRules（route allow 列表）都按 consumer 维度分片到同一个 ConfigMap。

**理由**：
- matchRules 也会随消费者和授权关系增长而膨胀
- 按 consumer 维度组织，CRUD 时只需更新一个 ConfigMap
- Istio 侧合并逻辑：consumers 直接拼接，matchRules 按 ingress 合并 allow 数组

### 2.5 发布模式：异步事件驱动

**决策**：用户请求同步写 MySQL（状态 PENDING），异步事件触发分片 ConfigMap 写入，成功后更新状态为 PUBLISHED。

**理由**：
- 用户请求秒回，不阻塞在 K8s API 调用上
- 解耦持久化和运行时配置，两者状态独立可观测
- 失败时标记 FAILED，页面提供重试按钮

## 3. 架构总览

```
┌─────────────────────────────────────────────────────────────────┐
│                        用户请求                                   │
└─────────────────────┬───────────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  Service 层 (HigressApplicationServiceImpl)                      │
│  - 写 MySQL (publish_status = PENDING)                           │
│  - 发布 ConsumerPublishEvent                                     │
│  - 返回成功                                                      │
└─────────────────────┬───────────────────────────────────────────┘
                      ▼ (Spring ApplicationEvent, @Async)
┌─────────────────────────────────────────────────────────────────┐
│  KeyAuthPublishEventListener                                     │
│  - 调用 KeyAuthShardingPublisher                                 │
│  - 成功: 更新 publish_status = PUBLISHED                         │
│  - 失败: 更新 publish_status = FAILED                            │
└─────────────────────┬───────────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│  KeyAuthShardingPublisher                                        │
│  - hash(consumerName) % 64 → 确定分片                            │
│  - 从 MySQL 读取该分片所有 consumer + authorization               │
│  - 生成 YAML 片段写入 ConfigMap (hi-key-auth-shard-{N})           │
└─────────────────────┬───────────────────────────────────────────┘
                      ▼ (ConfigMap 变更触发)
┌─────────────────────────────────────────────────────────────────┐
│  Higress Controller (Go)                                         │
│  - onShardConfigMapChanged: 检测 hi-key-auth-shard-* 变更        │
│  - 触发 full xDS push                                            │
│  - convertIstioWasmPlugin → mergeShardedConfigMaps               │
│    - 读取所有 resourceRefs 引用的 ConfigMap                       │
│    - 合并 consumers 到 defaultConfig                             │
│    - 按 ingress 合并 matchRules 的 allow 列表                    │
│  - 生成最终 PluginConfig → 下发 Envoy                            │
└─────────────────────────────────────────────────────────────────┘
```

## 4. 数据模型

### 4.1 MySQL 表

```sql
-- 消费者表
CREATE TABLE higress_consumer (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    consumer_id VARCHAR(128) NOT NULL,
    gw_instance_id VARCHAR(128) NOT NULL,
    name VARCHAR(128) NOT NULL,
    description VARCHAR(512),
    credential_key VARCHAR(512) NOT NULL,
    credential_type VARCHAR(32) DEFAULT 'KEY_AUTH',
    location_type VARCHAR(32) DEFAULT 'BEARER',
    location_key_name VARCHAR(128) DEFAULT 'Authorization',
    enable TINYINT(1) DEFAULT 1,
    publish_status VARCHAR(16) DEFAULT 'PENDING',
    UNIQUE KEY uk_consumer_gw (consumer_id, gw_instance_id)
);

-- 授权关系表
CREATE TABLE higress_authorization (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    auth_id VARCHAR(128) NOT NULL,
    gw_instance_id VARCHAR(128) NOT NULL,
    app_id VARCHAR(128) NOT NULL,
    grant_type VARCHAR(32) NOT NULL,
    grant_target_id VARCHAR(256) NOT NULL,
    publish_status VARCHAR(16) DEFAULT 'PENDING',
    UNIQUE KEY uk_auth_id_gw (auth_id, gw_instance_id)
);
```

### 4.2 分片 ConfigMap 格式

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: hi-key-auth-shard-17
  labels:
    higress.io/biz-type: hi-key-auth-shard
    higress.io/internal: "true"
data:
  consumers: |
    - credential: Bearer xxx
      in_header: true
      in_query: false
      keys:
      - Authorization
      name: consumer-001
  matchRules: |
    - config:
        allow:
        - consumer-001
      configDisable: false
      ingress:
      - model-api-route-001
```

### 4.3 WasmPlugin CR（分片后）

```yaml
apiVersion: extensions.higress.io/v1alpha1
kind: WasmPlugin
metadata:
  name: key-auth.internal
spec:
  resourceRefs:
  - hi-key-auth-shard-0
  - hi-key-auth-shard-1
  - ...
  resourceTemplateSchema:
  - key: consumers
    value: consumers
  - key: matchRules
    value: matchRules
  defaultConfig:
    global_auth: false
  # matchRules 为空，由 Controller 从 ConfigMap 合并
```

## 5. 改动清单

### 5.1 harmony-gateway-admin（控制台）

| 文件 | 改动 |
|------|------|
| `HigressConsumer.java` | 新增实体 + publish_status 字段 |
| `HigressAuthorization.java` | 新增实体 + publish_status 字段 |
| `HigressConsumerMapper.java` | MyBatis Mapper |
| `HigressAuthorizationMapper.java` | MyBatis Mapper |
| `HigressConsumerDAO.java` | MySQL DAO（替代 ConfigMapAppAdapter） |
| `HigressAuthorizationDAO.java` | MySQL DAO（替代 ConfigMapAuthorizationAdapter） |
| `HigressConsumerMysqlMigrator.java` | 启动迁移：ConfigMap + WasmPlugin → MySQL |
| `HigressAuthorizationMysqlMigrator.java` | 启动迁移：ConfigMap + WasmPlugin → MySQL |
| `ConsumerPublishEvent.java` | Spring 异步事件 |
| `KeyAuthPublishEventListener.java` | 异步事件监听器 |
| `KeyAuthShardingPublisher.java` | 分片 ConfigMap 写入核心逻辑 |
| `PublishStatusEnum.java` | 发布状态枚举 |
| `HigressApplicationServiceImpl.java` | 改为异步事件驱动 |
| `HigressAuthorizationServiceImpl.java` | 改为异步事件驱动 |
| `HigressAppQueryServiceImpl.java` | 从 MySQL 查询 |
| `AuthorizationRelQueryServiceImpl.java` | 从 MySQL 查询 |
| `ApplicationController.java` | 新增 retryPublish API |
| DDL SQL | 建表语句 |

### 5.2 higress-console（SDK）

| 文件 | 改动 |
|------|------|
| `V1alpha1WasmPluginSpec.java` | 新增 resourceRefs + resourceTemplateSchema 字段 |
| `ResourceTemplateSchemaEntry.java` | 新增模板映射模型 |

### 5.3 higress（Controller）

| 文件 | 改动 |
|------|------|
| `wasmplugin.proto` | 新增 resource_refs、resource_template_schema、ResourceTemplateSchemaEntry |
| `wasmplugin.pb.go` | 手动添加字段（待 buf generate 重新生成） |
| `ingress_config.go` | 新增 mergeShardedConfigMaps + onShardConfigMapChanged |

## 6. 待办事项

### 6.1 必须完成

- [ ] 安装 `buf`，在 higress 仓库执行 `buf generate` 重新生成 `wasmplugin.pb.go`
- [ ] 搭建 higress controller 构建环境（`external/` 目录），验证 Go 编译通过
- [ ] 部署 higress controller 到 ls-test 环境
- [ ] 端到端验证：创建消费者 → 分片 ConfigMap 生成 → Controller 合并渲染 → Envoy 鉴权生效
- [ ] 验证分片 ConfigMap 变更后，xDS push 是否及时触发
- [ ] 压测：8K consumer 场景下，分片写入性能和 xDS 生效延迟

### 6.2 后续优化

- [ ] 前端展示 publish_status 状态标签（待生效/已生效/生效失败）
- [ ] 前端"重试发布"按钮（调用 `/application/retryPublish`）
- [ ] WasmPlugin CR 瘦身：当分片 ConfigMap 就绪后，清理 CR 中的 defaultConfig.consumers 和 matchRules
- [ ] 动态扩容：当单个分片超过 200KB 时，自动扩展桶数（reHash）
- [ ] 迁移完成后清理：删除 `ConfigMapAppAdapter`、`ConfigMapAuthorizationAdapter` 及相关迁移器
- [ ] `HigressApplicationPublisher` 和 `HigressAuthorizationPublisher` 可以删除（已被异步事件替代）
- [ ] 考虑 MCP Server 配置的分片（同样的机制可复用）

### 6.3 风险点

- **ConfigMap watch 延迟**：64 个分片 ConfigMap 变更时，Controller 需要重新读取所有分片合并。如果变更频繁，可能导致 xDS push 风暴。建议加 debounce（合并短时间内的多次变更为一次 push）。
- **数据一致性**：异步发布期间，MySQL 中的数据和运行时配置可能短暂不一致（PENDING 状态）。这是设计上允许的，页面会展示状态。
- **proto 兼容性**：新增的 field number (104, 105) 不能与未来上游 Higress 的字段冲突。建议使用更大的 field number（如 200+）或与上游沟通预留。
