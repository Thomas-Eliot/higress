# Higress 开源版仓库依赖关系

## 1. 整体架构

Higress 采用 **主仓库 + git submodule** 的架构。所有子仓库作为 submodule 引入主仓库，构建时通过 `prebuild.sh` 脚本拷贝到 `external/` 目录，供 Go/Bazel 编译系统使用。

```
higress (主仓库)
│
├── istio/                      # Istio 相关子仓库
│   ├── istio      (Pilot 控制面)
│   ├── proxy      (Envoy 构建入口 + Istio 扩展)
│   ├── api        (Istio CRD / Proto 定义)
│   ├── client-go  (Istio CRD 的 Go client)
│   └── pkg        (Istio 公共 Go 库)
│
├── envoy/                      # Envoy 相关子仓库
│   ├── envoy           (Envoy 核心, fork 自 higress-group/envoy)
│   └── go-control-plane (xDS Go SDK)
│
├── api/                        # Higress 自身的 CRD 定义
├── pkg/                        # Higress 控制器逻辑
├── cmd/                        # Higress 二进制入口
├── hgctl/                      # CLI 工具
├── plugins/wasm-go/            # Wasm 插件 (Go)
└── helm/                       # Helm Chart
```

## 2. 各仓库职责

### 2.1 主仓库 (`github.com/alibaba/higress/v2`)

Higress 自身的控制面逻辑，包括：

- `api/` — Higress CRD 定义（McpBridge、Http2Rpc 等）
- `pkg/` — 控制器实现（WasmPlugin 管理、Ingress 转换等）
- `cmd/` — higress 二进制入口
- `hgctl/` — 命令行管理工具
- `helm/` — Helm Chart 部署模板
- `plugins/wasm-go/` — Go 语言 Wasm 插件集合

### 2.2 `envoy/envoy` — Envoy 核心 + Higress 定制

Fork 自 `higress-group/envoy`，基于 Envoy 1.27。包含三部分内容：

| 内容 | 说明 |
|------|------|
| Envoy 原生代码 | 上游 Envoy 的全部核心代码和数百个原生扩展（cors、wasm、lua、ext_authz 等） |
| Higress 新增扩展 | 完全新增的 filter，如 `rate_limit_quota_apig`（大规模消费者限流） |
| Higress 条件编译改动 | 通过 `#ifdef HIGRESS` 宏对已有模块的定制，涉及约 73 个文件 |

Higress 条件编译改动覆盖的模块包括：

- `http_connection_manager` — 连接管理核心逻辑
- `custom_response` — AI fallback 场景优化
- `wasm` — Wasm filter 增强（tracing、foreign function 等）
- `ext_authz` — 外部鉴权扩展
- `redis` — Redis 协议相关定制
- `on_demand` — 按需路由加载
- `admin` — 管理接口
- `SDS / SRDS` — 证书下发和 Scoped RDS

### 2.3 `istio/proxy` — Envoy 构建入口 + Istio 扩展

模块名 `io_istio_proxy`，是最终 Envoy 二进制的 **Bazel 构建入口**。它做两件事：

**承载 Istio 侧的 C++ 扩展：**

- `extensions/metadata_exchange` — 服务间元数据交换
- `extensions/stackdriver` — 可观测性上报
- `extensions/access_log_policy` — 访问日志策略
- `src/istio/authn` — mTLS 认证

**控制最终产物的扩展集合：**

`bazel/extension_config/extensions_build_config.bzl` 文件是一张"菜单"，列出最终 Envoy 二进制中包含哪些扩展。例如：

```python
# 来自 envoy/envoy 的扩展，通过 @envoy// 引用
"envoy.filters.http.wasm":  "//source/extensions/filters/http/wasm:config",
"envoy.filters.http.rate_limit_quota_apig": "//source/extensions/filters/http/rate_limit_quota_apig:config",

# 来自 istio/proxy 自身的扩展
# (在 extensions/ 目录下，通过本地路径引用)
```

### 2.4 `istio/istio` — Pilot 控制面

Istio 的 Pilot 组件，Higress 基于此构建控制面，负责：

- xDS 协议服务端（向 Envoy 下发配置）
- 服务发现和路由规则转换
- 证书管理（SDS）

### 2.5 `istio/api`、`istio/client-go`、`istio/pkg`

Istio 生态的基础库：

| 仓库 | 职责 |
|------|------|
| `istio/api` | Istio CRD 的 Proto 定义（VirtualService、DestinationRule 等） |
| `istio/client-go` | 上述 CRD 的 Go clientset（自动生成） |
| `istio/pkg` | Istio 公共 Go 工具库 |

### 2.6 `envoy/go-control-plane`

Envoy xDS 协议的 Go SDK，Pilot 通过它向 Envoy 下发配置。

## 3. 依赖关系图

```
┌─────────────────────────────────────────────────────────────────┐
│                        Higress 主仓库                            │
│                  github.com/alibaba/higress/v2                   │
│                                                                  │
│   api/  pkg/  cmd/  hgctl/  helm/  plugins/wasm-go/             │
└───────────────────┬─────────────────────────────────────────────┘
                    │
                    │ go.mod replace => ./external/*
                    │
     ┌──────────────┼──────────────┬────────────────┐
     ▼              ▼              ▼                ▼
 istio/istio    istio/api    istio/client-go    istio/pkg
  (Pilot)      (CRD Proto)   (Go Client)       (公共库)
     │              ▲              │                │
     └──────────────┴──────────────┘                │
     │         Pilot 依赖 api/client-go             │
     │                                              │
     ▼                                              │
 go-control-plane ◄─────────────────────────────────┘
  (xDS Go SDK)

─ ─ ─ ─ ─ ─ ─ ─ ─ Go 构建 / Bazel 构建 分界线 ─ ─ ─ ─ ─ ─ ─ ─

 istio/proxy (Bazel 构建入口)
     │
     │  WORKSPACE: http_archive(name = "envoy", ...)
     │  extensions_build_config.bzl: 扩展注册表
     │
     ▼
 envoy/envoy (Envoy 核心 + Higress 定制)
  ├── Envoy 原生扩展 (数百个)
  ├── Higress 新增扩展 (rate_limit_quota_apig 等)
  └── Higress #ifdef 条件编译改动 (73 个文件)
```

## 4. 构建流程

### 4.1 prebuild — 子仓库同步

所有构建目标都依赖 `prebuild`，它做两件事：

1. `git submodule update --init` — 拉取所有子仓库
2. `prebuild.sh` — 将 `istio/*` 和 `envoy/*` 拷贝到 `external/` 目录

```bash
# prebuild.sh 核心逻辑
cp -RP istio/istio   external/istio
cp -RP istio/api     external/api
cp -RP envoy/envoy   external/envoy
cp -RP istio/proxy   external/proxy
# ...
```

拷贝后主仓库的 `go.mod` 通过 `replace` 指令直接引用 `external/` 下的本地代码：

```go
replace istio.io/istio      => ./external/istio
replace istio.io/api         => ./external/api
replace istio.io/client-go   => ./external/client-go
replace istio.io/pkg         => ./external/pkg
```

### 4.2 控制面构建

```
make build
  └── prebuild → 同步子仓库到 external/
  └── go build ./cmd/...
        ├── 主仓库 pkg/ (Higress 控制器)
        └── external/istio (Pilot) + external/api + external/pkg + ...
  └── 产出: higress 二进制
```

### 4.3 数据面构建

```
make build-envoy
  └── prebuild → 同步子仓库到 external/
  └── 在构建容器中执行:
        external/proxy (istio/proxy) 的 Bazel 构建
          ├── @envoy → external/envoy (envoy/envoy)
          ├── istio/proxy 自身的扩展
          └── extensions_build_config.bzl 控制包含哪些扩展
  └── 产出: envoy 二进制 (tar.gz)
```

### 4.4 镜像打包

```
make build-istio       → docker.pilot   (Higress 控制面镜像)
make build-gateway-*   → docker.proxyv2 (Envoy 数据面镜像)
```

## 5. `envoy/envoy` 与 `istio/proxy` 的关系详解

这两者容易混淆，核心区别：

|  | envoy/envoy | istio/proxy |
|--|-------------|-------------|
| **本质** | Envoy 的完整源码（fork） | Envoy 的"壳"和构建入口 |
| **语言** | C++ | C++ |
| **构建系统** | 被引用（作为 Bazel 依赖） | 构建入口（WORKSPACE 在此） |
| **扩展内容** | Envoy 原生扩展 + Higress 底层定制 | Istio 层扩展（metadata_exchange 等） |
| **修改频率** | 较少（涉及 Envoy 核心） | 较少（Istio 扩展相对稳定） |

它们**不是同级关系**，而是上下层：

- `istio/proxy` 是最终 Envoy 二进制的 **Bazel 构建入口**
- `envoy/envoy` 是 proxy 的 **核心依赖**（通过 `@envoy` 引用）
- proxy 的 `extensions_build_config.bzl` 决定最终二进制里包含 envoy 的哪些扩展
- 两者的扩展代码最终编译进同一个 Envoy 二进制

```
最终 Envoy 二进制 = envoy/envoy 的代码 (核心 + 原生扩展 + Higress 定制)
                  + istio/proxy 的代码 (Istio 扩展)
                  统一由 proxy 的 Bazel 构建系统编译
```

## 6. 修改影响矩阵

| 修改位置 | 影响范围 | 需要重建 |
|----------|----------|----------|
| 主仓库 `pkg/`、`cmd/` | Higress 控制器逻辑 | higress 二进制 |
| 主仓库 `api/` | Higress CRD 定义 | higress 二进制 + Helm CRDs |
| `istio/istio` | Pilot 控制面 | pilot 镜像 |
| `istio/api` | Istio CRD Proto | 需重新生成 client-go → 重编主仓库和 Pilot |
| `envoy/envoy` | Envoy 核心或扩展 | 重建 Envoy 二进制 → proxyv2 镜像 |
| `istio/proxy` | Istio 扩展或构建配置 | 重建 Envoy 二进制 → proxyv2 镜像 |
| `plugins/wasm-go/` | Wasm 插件 | 仅对应插件的 .wasm 文件，不影响核心 |
| `helm/` | 部署模板 | 无需编译，直接生效 |
