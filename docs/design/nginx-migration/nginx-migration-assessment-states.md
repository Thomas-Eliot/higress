# Nginx 迁移 - 评估结果状态说明

## 概述

Nginx Ingress 迁移至 Higress 的评估流程中，系统会对每个 Ingress 资源的注解进行兼容性分析，逐层汇总得出风险等级和整体迁移结论。

---

## 1. 注解兼容性分类（AnnotationCompatibilityLevel）

评估过程中，每个 Nginx Ingress 注解会被归入以下分类：

| 分类 | 枚举值 | 说明 |
|------|--------|------|
| 完全兼容 | `FULLY_COMPATIBLE` | Higress 原生支持该注解，无需任何修改即可迁移 |
| 可等价替换 | `REPLACEABLE` | Higress 不直接支持该注解，但有等价的替代方案可实现相同功能 |
| 部分兼容 | `PARTIAL` | 注解的部分功能可迁移，但某些参数或行为在 Higress 中有差异 |
| 不兼容 | `INCOMPATIBLE` | Higress 无法支持该注解功能，需要架构层面的替代方案或放弃该功能 |
| 无需迁移 | `NO_MIGRATION_NEEDED` | 该注解为 Nginx Ingress 内部机制使用，在 Higress 中无对应概念也无需对应 |

---

## 2. Ingress 风险等级（RiskLevel）

每个 Ingress 资源根据其所有注解的兼容性分类，汇总得出一个风险等级：

| 风险等级 | 枚举值 | 判定规则 | 含义 |
|---------|--------|---------|------|
| 兼容 | `COMPATIBLE` | 所有注解均为"完全兼容"或"无需迁移" | 该 Ingress 可直接迁移，无需额外适配 |
| 中风险 | `MEDIUM` | 存在"部分兼容"或"可等价替换"的注解，但无不兼容项 | 该 Ingress 可迁移，但需要进行注解替换或配置调整 |
| 高风险 | `HIGH` | 存在"不兼容"或"未知"的注解 | 该 Ingress 存在阻塞性问题，需人工介入处理后才能迁移 |

**判定优先级**：不兼容/未知 > 部分兼容/可替换 > 完全兼容/无需迁移

---

## 3. 整体评估结论（canMigrate）

评估完成后，系统综合所有 Ingress 的分析结果，给出一个总体迁移结论：

| 结论 | 含义 |
|------|------|
| `canMigrate = true` | 不存在阻塞性问题（BlockingIssues 为空），可以执行迁移 |
| `canMigrate = false` | 存在阻塞性问题，需先解决后才能继续迁移流程 |

阻塞性问题（BlockingIssue）包含：问题类型、涉及注解、功能分类、影响的 Ingress 列表、解决方案建议和风险说明。

---

## 4. 评估结果汇总（Summary）

评估结果中包含一个 Summary 统计，按兼容性分类汇总 Ingress 数量：

| 字段 | 说明 |
|------|------|
| `totalIngresses` | 参与评估的 Ingress 总数 |
| `fullyCompatible` | 完全兼容的 Ingress 数量 |
| `replaceable` | 可等价替换的 Ingress 数量 |
| `incompatible` | 不兼容的 Ingress 数量 |
| `partial` | 部分兼容的 Ingress 数量 |
| `noMigrationNeeded` | 无需迁移的 Ingress 数量 |
| `unknown` | 未知状态的 Ingress 数量 |

---

## 5. 状态流转全景

```
解析 Ingress 注解
       │
       ▼
┌─────────────────────────┐
│  逐条注解兼容性分类       │
│  FULLY_COMPATIBLE        │
│  REPLACEABLE             │
│  PARTIAL                 │
│  INCOMPATIBLE            │
│  NO_MIGRATION_NEEDED     │
└───────────┬─────────────┘
            │ 汇总
            ▼
┌─────────────────────────┐
│  Ingress 风险等级判定     │
│  COMPATIBLE / MEDIUM / HIGH │
└───────────┬─────────────┘
            │ 综合所有 Ingress
            ▼
┌─────────────────────────┐
│  整体迁移结论            │
│  canMigrate: true/false  │
└─────────────────────────┘
```
