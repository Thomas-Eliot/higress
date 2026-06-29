# 分支管理 & 多仓库新手指南

> 面向第一次接触本工作区的人。回答三个问题：**这里有哪些仓库、各自干什么、改完代码往哪个分支 / remote 推。**
>
> 只讲「git 拓扑 + 分支 + 推送约定」。Bazel / go.mod 的**构建依赖关系**请配合看 [`higress-repo-dependencies.md`](./higress-repo-dependencies.md)，本文不重复。

---

## 0. 30 秒速查

| 你想做的事 | 落在哪个目录 | 推到哪 |
|---|---|---|
| 改 Higress 控制器 / CRD 转换 | 父仓库 `pkg/` `cmd/` `api/` | 父仓库 `apsara-main` → **`origin-intranet`** |
| 改 QuotaRule Controller / Pilot | **`istio/istio`** 子模块 | `csb2/istio` 的 `istio-1.19` |
| 改 QuotaRule proto / pb.go | `istio/api` 子模块 | `csb2/istio_api` 的 `istio-1.19` |
| 改 `rate_limit_quota_apig` C++ filter | **`envoy/envoy`** 子模块 | `csb2/envoy` 的 `envoy-1.27` |
| 改 quota 决策服务 | `ratelimit-quota-server` 子模块 | `csb2/ratelimit-quota-server` 的 `master` |
| 改 `golang-filter.so` (MCP / Go SDK) | `plugins/golang-filter`（在父仓库内） | 父仓库 `apsara-main` |
| 编译验证 / `go build` 实际读的源 | **`external/*`（gitignored，勿提交）** | — 不推 |

> ⚠️ **三条最容易踩的坑**，先记住：
> 1. **`istio/*`、`envoy/*` 才是 git 真源；`external/*` 是构建拷贝、被 `.gitignore` 忽略。** 改 `external/istio` 不会进版本库。详见 [§4](#4-canonical-源-vs-构建拷贝最重要的区别)。
> 2. **父仓库 `apsara-main` 的 canonical 落点是 `origin-intranet`（公司 gitlab），不是 `origin`（github fork，已严重落后）。** 详见 [§2](#2-父仓库的三个-remote)。
> 3. **`golang-filter.so` 不走 `envoy/envoy` 子模块**，它从自己 `go.mod` 的 pin 联网拉 Go SDK。改 envoy 子模块对 `.so` 无影响。详见 [§5.2](#52-pluginsgolang-filter--golang-filterso)。

---

## 1. 仓库全景

本工作区 = **1 个父仓库 + 9 个 git 子模块 + 若干非子模块的工作目录**。

```
higress-opensource/                       ← 父仓库 (csb2/higress-gateway)，当前分支 apsara-main
│
├── api/ pkg/ cmd/ hgctl/ helm/           ← 父仓库自身代码（Higress 控制面）
├── plugins/                              ← 父仓库自身代码（wasm-go 插件 + golang-filter）
│
├── istio/                                ← 子模块组（branch: istio-1.19）
│   ├── istio        [submodule]  csb2/istio              ← Pilot 控制面 + QuotaRule Controller
│   ├── api          [submodule]  csb2/istio_api          ← Istio + QuotaRule CRD proto / pb.go
│   ├── client-go    [submodule]  csb2/istio_client-go    ← CRD 的 Go client
│   ├── pkg          [submodule]  csb2/istio_pkg          ← Istio 公共库
│   └── proxy        [submodule]  csb2/istio_proxy        ← Envoy 的 Bazel 构建入口
│
├── envoy/
│   ├── envoy        [submodule]  csb2/envoy   (envoy-1.27)  ← Envoy 核心 + apig C++ filter
│   └── go-control-plane [submodule] csb2/envoy_go-control-plane ← xDS Go SDK
│
├── ratelimit-quota-server [submodule]  csb2/ratelimit-quota-server (master) ← quota 决策服务（网关 sidecar）
├── aigateway-ratelimit-quota-knownow [submodule] lvshui/...  (main) ← 内部版参考代码 + 设计文档（只读参考）
│
├── csb2-go-control-plane/                ← 非子模块，手工 clone，gitignored（见 §5.1）
├── external/                             ← 非子模块，构建拷贝，gitignored（见 §4）
├── reference_repositories/wasm-go/       ← 非子模块，参考
└── higress, plugins/golang-filter/*.so   ← 构建产物，gitignored
```

`.gitmodules` 是唯一权威的子模块清单；`git submodule status` 看当前各子模块 pin 在哪个 commit。

---

## 2. 父仓库的三个 remote

```
origin           git@github.com:Thomas-Eliot/higress.git          (github 个人 fork — 已严重落后，stale)
origin-intranet  git@gitlab.alibaba-inc.com:csb2/higress-gateway  (公司 gitlab — canonical，推这里)
upstream         git@github.com:alibaba/higress.git               (alibaba 开源上游 — 只 fetch，不直接推)
```

- **当前工作分支：`apsara-main`。** 这是公司内部主线（不是开源 `main`）。
- **canonical / 推送目标是 `origin-intranet`。** 虽然 `git` 里 `apsara-main` 的默认 `@{upstream}` 指向 `origin/apsara-main`（github fork），但团队约定真正的落点是 `origin-intranet`（gitlab）。`origin` 是早期 fork 的残留、落后很多，不要往那推。
  - `origin-intranet` 的 `pre-push` 钩子带 **AK / 密钥泄漏扫描**，推送时会跑。
- `upstream`（alibaba/higress）是开源上游，用来同步社区改动，平时只 fetch。

```bash
# 推父仓库改动（apsara-main → 公司 gitlab）
git push origin-intranet apsara-main
```

> 分支命名惯例：长期主线 `apsara-main`；临时修复 `hotfix/issue-<n>`、`bugfix/<desc>`；功能 `feat/<desc>`。开源对照分支是 `main`（= upstream alibaba/higress）。

---

## 3. 子模块分支管理

每个子模块在 `.gitmodules` 里固定了 **url + 跟踪分支**，父仓库则用一个 **commit pin**（`git submodule status` 显示）锁定具体版本。

| 子模块路径 | remote (canonical) | 跟踪分支 |
|---|---|---|
| `istio/istio` | `csb2/istio` | `istio-1.19` |
| `istio/api` | `csb2/istio_api` | `istio-1.19` |
| `istio/client-go` | `csb2/istio_client-go` | `istio-1.19` |
| `istio/pkg` | `csb2/istio_pkg` | `istio-1.19` |
| `istio/proxy` | `csb2/istio_proxy` | `istio-1.19` |
| `envoy/go-control-plane` | `csb2/envoy_go-control-plane` | `istio-1.19` |
| `envoy/envoy` | `csb2/envoy` | **`envoy-1.27`** |
| `ratelimit-quota-server` | `csb2/ratelimit-quota-server` | `master` |
| `aigateway-ratelimit-quota-knownow` | `lvshui/aigateway-...` | `main` |

### 单个子模块可能有多个 remote

子模块在本地往往配了不止一个 remote。以 `istio/istio` 为例：

```
csb2     git@gitlab.alibaba-inc.com:csb2/istio.git   ← canonical，push 走这里
origin   https://github.com/higress-group/istio      ← 首次同步来历，非 canonical
本地分支: istio-1.19-csb2  →  tracking  csb2/istio-1.19
```

`envoy/envoy` 类似，配了 `csb2`（canonical）、`github`（Thomas-Eliot fork，曾用于 ECS amd64 编译）、`origin`（higress-group）三个 remote。

**约定：子模块改动一律推 `csb2/*`。** github 上的 `origin`/`github` remote 只是来历或临时编译用途。

### 改子模块 + 更新父仓库 pin 的标准流程

```bash
# 1. 进子模块改代码、提交、推 csb2
cd istio/istio
# ...edit...
git commit -am "fix(quotarule): ..."
git push csb2 istio-1.19-csb2:istio-1.19

# 2. 回父仓库，把新的子模块 commit 记成 pin
cd ../..
git add istio/istio
git commit -m "chore(submodule): bump istio/istio to <sha>"
git push origin-intranet apsara-main
```

> 父仓库提交里看到的 `chore(submodule): bump envoy/envoy to c42a2919` 就是「只更新 pin」的提交。

---

## 4. canonical 源 vs 构建拷贝（最重要的区别）

这是本工作区**最反直觉**的一点，务必理解：

```
istio/istio   ← git 真源（submodule，提交/推送在这里）
external/istio ← 构建拷贝（go build 实际读这里，但 .gitignore 忽略，改了不进版本库）
```

- `go.mod` 里写的是 `replace istio.io/istio => ./external/istio`（以及 api/pkg/client-go/go-control-plane/proxy 同理）。**所以 `go build` / 编译验证读的是 `external/*`。**
- `external/*` 由 `prebuild.sh` 从 `istio/*`、`envoy/*` 子模块 `cp -RP` 拷贝而来，并被 `.gitignore`（第 13 行 `external/`）忽略。
- **结论：改动要落在 `istio/*` / `envoy/*` 子模块（git 真源），编译验证可在 `external/*` 上跑；两边必须手动保持同步。** 只改 `external/istio` 等于白改，提交时根本看不到。

> 实操：通常在 `external/istio` 上快速 `go build` 迭代验证，定稿后把改动 `cp` 回 `istio/istio` 子模块再 commit/push。注意个别文件有细微差异（例如 `controller.go` 的泛型标注 `NewDelayedInformer[controllers.Object]` 在 `istio/istio` 有、`external` 靠 Go 推断可省），镜像构建时各自保留即可。

`external/package/` 下放的是**预编译好的 envoy 二进制产物**（`*.tar.gz` / `*.sha256`），也是 gitignored，用于免编译组装镜像。

---

## 5. 几个非子模块、容易困惑的目录

### 5.1 `csb2-go-control-plane/`

- **不是子模块**（不在 `.gitmodules`），是手工 `git clone` 的 `csb2/envoy_go-control-plane.git` 副本，被 `.gitignore`（第 25 行）忽略。
- 用途：`ratelimit-quota-server/go.mod` 里 `replace github.com/envoyproxy/go-control-plane => ../csb2-go-control-plane`。quota-server 编译需要里面的 `quota_apig` 包，而该包只在公司内网 gitlab 路径下有；用本地副本绕开拉取问题。
- 和子模块 `envoy/go-control-plane` 同源（都是 `csb2/envoy_go-control-plane`），但**服务于不同的 go module**：子模块给主仓库构建用，`csb2-go-control-plane` 专给 quota-server 用。曾被误改成 `../envoy/go-control-plane`（那里没有 `quota_apig` 包），别重蹈覆辙。

### 5.2 `plugins/golang-filter/` → `golang-filter.so`

- 属于**父仓库自身代码**，构建出 `golang-filter.so`（MCP server 等 Go filter），网关运行时从 `/var/lib/istio/envoy/golang-filter.so` 加载。
- **关键坑：这个 `.so` 不走 `envoy/envoy` 子模块。** 它的 Go SDK（`contrib/golang/.../shim.go` 等）由 `plugins/golang-filter/go.mod` 里的 `replace github.com/envoyproxy/envoy => github.com/higress-group/envoy@<pin>` **联网拉取**。
- 因此：在 `csb2/envoy` fork 里改了 `shim.go`、切了子模块分支，对 `.so` **毫无影响**。要把修复打进 `.so`，得临时把 `replace` 指到本地带修复的 SDK 再重编（做法见项目记忆 / `docs/development`）。

### 5.3 `aigateway-ratelimit-quota-knownow/`

- 子模块（`lvshui/...`，branch `main`），是 **内部版（`Ingress/istio`、`Ingress/envoy`、`Ingress/ratelimit-quota-server`）的参考代码快照 + 设计文档**（`ARCHITECTURE_OVERVIEW.md`、`COMMUNICATION_DESIGN.md`、`DATA_MODEL.md`）。
- 用途是**对照参考 / 设计溯源**，理解 apig filter、冷热分离、SyncCheck 等设计从哪来。它**不参与本仓库的编译**。
- 注意：其中 `aigateway-ratelimit-quota-knownow/envoy/...` 是 apig C++ filter 的**旧拷贝、行号已漂移**；走读 / 排障以 `envoy/envoy/source/.../rate_limit_quota_apig/` 这份**新权威拷贝**为准。

### 5.4 `reference_repositories/wasm-go/`

- 非子模块的参考目录，wasm-go 相关参考代码。只读参考，不参与构建。

---

## 6. 典型工作流串讲

**改 QuotaRule Controller（CRD → ConfigMap/EnvoyFilter 翻译逻辑）**
```
1. 编辑 external/istio/...   →  go build 验证
2. cp 回 istio/istio/...     →  commit + push csb2 istio-1.19
3. 父仓库 bump pin           →  push origin-intranet apsara-main
4. 重编 higress 二进制镜像（Controller 在 higress 容器，不是 pilot —— 见关联文档）
```

**改 apig C++ filter**
```
1. 编辑 envoy/envoy/source/.../rate_limit_quota_apig/
2. push csb2 envoy-1.27  →  父仓库 bump envoy/envoy pin  →  push origin-intranet
3. 重编 envoy 二进制（Bazel，ECS 8C，见 higress-envoy-build.md）
```

**改 quota 决策服务**
```
1. 编辑 ratelimit-quota-server/  （go.mod 里 replace 走 ../csb2-go-control-plane）
2. push csb2 master  →  父仓库 bump pin
3. 重编 quota-server 镜像，用 immutable tag（<commit>-<date>，别推 latest，会飘）
```

---

## 7. 常见坑速记

| 症状 / 疑问 | 真相 |
|---|---|
| 改了代码但 `git status` 看不到 | 改在了 `external/*`（gitignored 构建拷贝），真源在 `istio/*` / `envoy/*` 子模块 |
| 推到 github 没人看到 | 父仓库 canonical 是 `origin-intranet`（gitlab），不是 `origin`（落后的 fork） |
| 改了 envoy fork 的 shim.go，`.so` 行为没变 | `.so` 不走子模块，走 `plugins/golang-filter/go.mod` 的 higress-group pin |
| quota-server 编译找不到 `quota_apig` | go.mod 必须 replace 到 `../csb2-go-control-plane`，不是 `../envoy/go-control-plane` |
| 同 tag 镜像行为时好时坏 | 活动 tag（`latest` / `:quota-rule` / `:2.1.13`）会飘，长期部署一律用 immutable tag，校验时核验二进制内容而非只看 digest |
| 走读 apig filter 行号对不上 | 用 `envoy/envoy/...` 新权威拷贝，别用 `aigateway-...-knownow/envoy/...` 旧拷贝 |

---

## 8. 关联文档

- [`higress-repo-dependencies.md`](./higress-repo-dependencies.md) — 仓库间的**构建依赖关系**与 Bazel/go.mod 细节（本文的「为什么这么编」）
- [`higress-envoy-build.md`](./higress-envoy-build.md) — Envoy 二进制构建分工（C++ vs Go SDK）
- [`multi-arch-image-build.md`](./multi-arch-image-build.md) — 多架构镜像打包
- `aigateway-ratelimit-quota-knownow/ARCHITECTURE_OVERVIEW.md` — 限流三组件设计概览（内部版参考）
- `docs/design/`、`docs/operations/`、`docs/docs-ls/operations/` — 设计决策与排障记录
