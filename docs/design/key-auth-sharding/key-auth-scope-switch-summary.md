# key-auth 分片改造 — Scope 开关 ConfigMap 实现总结

## 本次改动概述

实现了 key-auth 分片模式下的 **Scope 开关 ConfigMap** 机制，解决了 CR matchRules 被清空后路由级（及 domain/service 级）插件实例的 CRUD 和前端展示问题。

---

## 核心设计

### 数据分层

| 存储位置 | 内容 | 用途 |
|----------|------|------|
| WasmPlugin CR `defaultConfig` | 全局配置（global_auth、keys 等） | 全局鉴权参数 |
| 分片 ConfigMap (`hi-key-auth-shard-*`) | consumers + matchRules（只有 allow + ingress） | 按 consumer hash 分片的鉴权数据 |
| 开关 ConfigMap (`hi-key-auth-route-switches`) | matchRules（只有 configDisable + scope） | 各 scope 的启用/禁用状态 |

### 关键原则

**分片模式下，key-auth 非全局 scope 的 CRUD 完全绕过 CR，只操作开关 ConfigMap。**

- 开关 ConfigMap 是 scope 启用/禁用状态的 **唯一数据源 (source of truth)**
- 避免了 CR 和 ConfigMap 双写的一致性问题
- Controller 合并时从开关 ConfigMap 读取 configDisable，从分片 ConfigMap 聚合 allow

---

## 改动文件清单

### Controller (Go) — `backend/higress`

| 文件 | 改动 |
|------|------|
| `pkg/ingress/config/ingress_config.go` | 重写 `mergeShardedConfigMaps`：区分开关 ConfigMap 和分片 ConfigMap；新增 `parseScopeSwitches`、`findSwitchByIngress`、`matchRuleScopeEquals`、`extractStringList` |
| `pkg/ingress/kube/configmap/controller.go` | ConfigMap 变更触发：增加 `hi-key-auth-route-switches` 的匹配 |

### Admin (Java) — `backend/harmony-gateway-admin`

| 文件 | 改动 |
|------|------|
| `HigressStrategyInstanceAdapter.java` | create/update/delete 分片模式短路：直接操作开关 ConfigMap；新增 `isShardingMode`、`isKeyAuthNonGlobalScope`、`extractScopeEntries` |
| `StrategyInstanceQueryServiceImpl.java` | `getResource` fallback 到开关 ConfigMap；`pageResource` 分片模式从开关 ConfigMap 构建实例列表；新增 `buildKeyAuthInstancesFromRouteSwitches`、`findKeyAuthInstanceByUid`、`buildRouteInstanceFromSwitch`、`readRouteSwitchEntries` |
| `KeyAuthShardingPublisher.java` | `buildMatchRulesYaml` 去掉 configDisable；`fullPublish` 包含开关 ConfigMap 到 resourceRefs；`addOrUpdateRouteSwitch`/`removeRouteSwitch` 泛化为支持 ingress/domain/service 三种 scope |

---

## CRUD 链路（分片模式）

### Create（路由/域名/服务级 key-auth 插件）
```
前端 → Controller → WasmPluginInstanceServiceImpl.create()
  → HigressStrategyInstanceAdapter.create()
    → isKeyAuthNonGlobalScope? && isShardingMode?
      → YES: keyAuthShardingPublisher.addOrUpdateRouteSwitch(scopeType, target, enabled)
      → NO: 走原有 CR 逻辑
```

### Enable / Disable
```
前端 → Controller → WasmPluginInstanceServiceImpl.enable/disable()
  → queryService.getResource(uid)
    → CR 查不到 → findKeyAuthInstanceByUid(从开关 ConfigMap 按 uid 匹配)
  → instanceAdapter.update()
    → isShardingMode? → YES: 直接更新开关 ConfigMap
```

### Delete
```
前端 → Controller → WasmPluginInstanceServiceImpl.delete()
  → queryService.getResource(uid) → 从开关 ConfigMap 找到实例
  → instanceAdapter.delete()
    → isShardingMode? → YES: 直接从开关 ConfigMap 删除条目
```

### List（前端插件列表页）
```
前端 → Controller → queryService.pageResource()
  → strategyName == "key-auth"?
    → buildKeyAuthInstancesFromRouteSwitches()
      → 读 CR 判断分片模式 → 读开关 ConfigMap → 构建实例列表
```

---

## Controller (Go) 合并逻辑

```
mergeShardedConfigMaps(wasmPlugin):
  1. 遍历 resourceRefs 中的所有 ConfigMap
     - 分片 ConfigMap: 收集 consumers + shardMatchRules
     - 开关 ConfigMap: 收集 switchMatchRules
  2. 合并 consumers → defaultConfig.consumers
  3. parseScopeSwitches(switchMatchRules) → 提取每个 scope 的 configDisable
  4. mergeMatchRulesByIngress(shardMatchRules) → 按 ingress 聚合 allow
  5. 组合最终 matchRules:
     - 有 allow 的 route: allow(from shards) + configDisable(from switches)
     - 只有开关的 scope: empty allow + configDisable
```

---

## 开关 ConfigMap 数据格式

```yaml
# hi-key-auth-route-switches
matchRules:
- configDisable: false
  ingress:
  - route-xxx
- configDisable: true
  domain:
  - domain-yyy
- configDisable: false
  service:
  - service-zzz
```

---

## 待优化项（非阻塞）

| # | 描述 | 优先级 |
|---|------|--------|
| 1 | `isShardingMode` 每次 CRUD 都读 CR，可缓存 | P2 |
| 2 | `getResource` 对非 key-auth 插件也会触发 fallback（非分片模式快速返回 null，影响小；需入参有 strategyName 才能优化，暂不做） | P2 |
| 3 | 分片模式下 create 跳过了唯一性校验（幂等覆盖，行为合理） | P2 |
| 4 | `removeRouteSwitch` 三参数版本没调 `updateResourceRefsIfNeeded`（不影响功能） | P2 |

---

## 分支状态

- `harmony-gateway-admin`: `key-auth-config-sharding` — 本次改动未 commit
- `higress`: `feat/key-auth-config-sharding` — 本次改动未 commit
- 编译验证：Go ✅ Java ✅
