# 项目文档

按软件工程生命周期组织的项目文档。

## 目录结构

```
docs/
├── design/                    # 设计阶段 — 架构设计、方案文档
│   ├── plugin-sharding/       # 插件配置分片设计
│   ├── key-auth-sharding/     # Key-Auth 分片改造
│   └── nginx-migration/       # Nginx Ingress 迁移方案
│
├── development/               # 开发阶段 — 开发指南、构建说明、仓库结构
│
├── testing/                   # 测试阶段 — 测试计划、测试报告
│   ├── nginx-migration/       # Nginx 迁移相关测试
│   ├── key-auth-sharding/     # Key-Auth 分片回归测试
│   └── quota-rule/            # QuotaRule 限流 e2e 测试
│
└── operations/                # 运维阶段 — 排障记录、运维脚本
```

## 分类说明

| 阶段 | 放什么 | 示例 |
|------|--------|------|
| design | 技术方案、架构设计、DDL、UML | 分片设计、迁移评估 |
| development | 构建流程、开发环境、仓库依赖 | higress-envoy-build.md |
| testing | 测试计划、回归报告、e2e 报告 | quota-rule/ 下的多窗口测试 |
| operations | 排障记录、故障复盘、运维脚本 | incident-*.md、patch-*.sh |
