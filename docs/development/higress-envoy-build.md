# Higress Envoy 构建方式详解

## 1. 构建概览

Higress 的数据面（Gateway）基于 Envoy 构建。由于 Envoy 本体的编译非常耗时（全量编译通常需要数小时），Higress 将构建分为两个阶段：

```
阶段一：编译 Envoy 二进制（Bazel / C++，耗时长，改动少时可跳过）
    ↓ 产出 envoy-*.tar.gz
阶段二：组装 Gateway 镜像（Docker，速度快，直接下载预编译 Envoy）
```

对应两条路径：

| 场景 | 命令 | 说明 |
|------|------|------|
| 修改了 Envoy C++ 代码 | `make build-envoy` → `make build-gateway-local` | 完整构建 |
| 未修改 Envoy C++ 代码 | `make build-gateway-local` | 快速构建，直接下载预编译 Envoy |

## 2. 源码组织

Envoy 构建涉及两个 submodule 仓库，构建前通过 `prebuild.sh` 拷贝到 `external/` 目录：

```
higress/
├── envoy/envoy          (submodule) ──拷贝──► external/envoy
├── istio/proxy          (submodule) ──拷贝──► external/proxy
└── external/package/    (构建产物输出目录)
```

两者的关系：

```
external/proxy  (Bazel workspace，构建入口)
  │
  │ WORKSPACE 中声明 @envoy 依赖
  │ bazel/extension_config/ 中定义扩展注册表
  │ extensions/ 中放置 Istio 侧 C++ 扩展
  │
  └──► external/envoy  (Envoy 完整源码，含 Higress 定制)
         ├── source/         Envoy 核心 + 所有内置扩展
         └── contrib/        Envoy contrib 扩展（Golang filter 等）
```

## 3. 完整构建流程（make build-envoy）

适用场景：修改了 `envoy/envoy` 或 `istio/proxy` 中的 C++ 代码，需要重新编译 Envoy 本体。

### 3.1 操作步骤

```bash
# 步骤 1：在 higress 仓库目录下，编译 Envoy 本体
make build-envoy

# 步骤 2：产物输出到 external/package/
#   external/package/envoy-alpha-<SHA>.tar.gz    (release 版，stripped)
#   external/package/envoy-symbol-<SHA>.tar.gz   (带符号版，用于调试)

# 步骤 3：将 tar.gz 上传到 OSS 或文件服务器
#   文件名需以架构名结尾，例如：
#     envoy-amd64.tar.gz
#     envoy-arm64.tar.gz

# 步骤 4：设置环境变量指向新的 Envoy 产物下载地址
export ENVOY_PACKAGE_URL_PATTERN="https://your-server.com/path/envoy-ARCH.tar.gz"

# 步骤 5：构建 Gateway 镜像（此时会使用你编译的 Envoy）
make build-gateway-local
```

### 3.2 内部调用链

`make build-envoy` 背后的完整执行过程：

```
make build-envoy  (Makefile.core.mk)
  │
  ├── 1. prebuild
  │     ├── git submodule update --init
  │     └── prebuild.sh
  │           拷贝 envoy/envoy  → external/envoy
  │           拷贝 istio/proxy  → external/proxy
  │           拷贝 istio/api 等 → external/api 等
  │           go mod tidy
  │
  └── 2. tools/hack/build-envoy.sh
        ├── source setup-istio-env.sh
        │     设置 ROOT、TARGET_ARCH、ISTIO_ENVOY_LINUX_RELEASE_URL
        │     设置 CONDITIONAL_HOST_MOUNTS（挂载 higress 根目录到容器 /parent）
        │
        ├── cd ${ROOT}/external/proxy
        │
        ├── 打 build-envoy.patch（将 WORKSPACE 改为使用本地 envoy）
        │
        ├── 追加容器挂载：
        │     external/package → /home/package
        │     external/envoy   → /home/envoy
        │
        └── 在构建容器中执行 make test_release
              └── scripts/release-binary.sh
                    └── bazel build --config=release //:envoy_tar
```

### 3.3 关键机制详解

#### 3.3.1 prebuild — 子仓库同步

所有构建目标都依赖 `prebuild`。`prebuild.sh` 的核心逻辑：

```bash
# 将 submodule 拷贝到 external/，如果已存在则跳过
for repo in "go-control-plane" "envoy"; do
    cp -RP envoy/$repo external/$repo
done

for repo in "api" "client-go" "pkg" "istio" "proxy"; do
    cp -RP istio/$repo external/$repo
done

go mod tidy
```

拷贝时保留 `.git` 引用，使得 `external/` 下的代码仍能进行 git 操作。

#### 3.3.2 Patch WORKSPACE — 切换为本地 Envoy 源码

`istio/proxy` 的 WORKSPACE 原始配置是从 GitHub 下载 envoy：

```python
# 原始：从 GitHub 下载特定 commit 的 envoy 源码
http_archive(
    name = "envoy",
    sha256 = ENVOY_SHA256,
    strip_prefix = ENVOY_REPO + "-" + ENVOY_SHA,
    url = "https://github.com/higress-group/envoy/archive/" + ENVOY_SHA + ".tar.gz",
)
```

`tools/hack/build-envoy.patch` 将其改为本地目录引用：

```python
# Patch 后：指向容器内挂载的本地 envoy 目录
local_repository(
    name = "envoy",
    path = "/home/envoy",
)
```

这样对 `envoy/envoy` submodule 的本地修改能立即参与编译，无需提交或推送。

#### 3.3.3 构建容器与挂载

```bash
BUILD_TOOLS_IMG="higress-registry.cn-hangzhou.cr.aliyuncs.com/higress/build-tools-proxy:release-1.19-..."
```

容器启动时的挂载关系：

```
宿主机                          容器内
─────────────────────────────────────────────
higress 根目录               → /parent
external/proxy (工作目录)    → 容器当前目录
external/envoy               → /home/envoy
external/package             → /home/package
```

容器以 root 用户运行，设置 `BUILD_ENVOY_BINARY_ONLY=1` 跳过 Wasm 构建。

#### 3.3.4 Bazel 编译

容器内实际执行 `istio/proxy` 的 `make test_release`，它调用 `scripts/release-binary.sh`：

```bash
export CC=clang CXX=clang++

# 编译 release 版（stripped，体积小）和 release-symbol 版（带调试符号）
for config in release release-symbol; do
    bazel build ${BAZEL_BUILD_ARGS} --config=${config} //:envoy_tar //:envoy.dwp
done
```

`//:envoy_tar` 这个 Bazel target 定义在 `istio/proxy` 的根 BUILD 文件中，它会：

1. 编译 `@envoy//` 下的全部 Envoy 核心代码
2. 根据 `extensions_build_config.bzl` 编译注册的所有扩展
3. 编译 `istio/proxy/extensions/` 下的 Istio 扩展
4. 将以上所有目标文件链接为一个完整的 Envoy 二进制
5. 打包为 tar.gz

#### 3.3.5 产物输出

编译完成后产物放在 `/home/package`（即宿主机 `external/package/`）：

```
external/package/
├── envoy-alpha-<SHA>.tar.gz      # release 版（stripped）
├── envoy-alpha-<SHA>.sha256      # 对应的 SHA256 校验和
├── envoy-symbol-<SHA>.tar.gz     # 带符号版
└── envoy-symbol-<SHA>.sha256
```

### 3.4 扩展注册表

`istio/proxy/bazel/extension_config/extensions_build_config.bzl` 是一张"菜单"，决定最终 Envoy 二进制中包含哪些扩展：

```python
ENVOY_EXTENSIONS = {
    # 引用 envoy/envoy 仓库中的扩展（通过 @envoy// 路径）
    "envoy.filters.http.wasm":                  "//source/extensions/filters/http/wasm:config",
    "envoy.filters.http.cors":                  "//source/extensions/filters/http/cors:config",
    "envoy.filters.http.rate_limit_quota_apig": "//source/extensions/filters/http/rate_limit_quota_apig:config",
    # ... 数百个
}

ENVOY_CONTRIB_EXTENSIONS = {
    # contrib 扩展，如 Golang filter
    "envoy.filters.http.golang": "//contrib/golang/filters/http/source:config",
    # ...
}

ISTIO_DISABLED_EXTENSIONS = ["envoy.transport_sockets.tcp_stats"]

# 最终集合 = ENVOY_EXTENSIONS - DISABLED + 选中的 CONTRIB
EXTENSIONS = dict(
    [(k,v) for k,v in ENVOY_EXTENSIONS.items() if k not in ISTIO_DISABLED_EXTENSIONS] +
    [(k,v) for k,v in ENVOY_CONTRIB_EXTENSIONS.items() if k in ISTIO_ENABLED_CONTRIB_EXTENSIONS]
)
```

> 注意：`//source/...` 路径前缀实际指向 `@envoy//source/...`，即 envoy/envoy 仓库中的代码。新增扩展时需在此文件中注册。

## 4. 快速构建流程（make build-gateway-local）

不重编 Envoy，直接使用预编译的 Envoy 产物构建 Gateway 镜像。

### 4.1 操作步骤

```bash
# 直接构建（使用默认的预编译 Envoy）
make build-gateway-local

# 或指定自编译的 Envoy 产物地址
ENVOY_PACKAGE_URL_PATTERN="https://your-server.com/envoy-ARCH.tar.gz" make build-gateway-local
```

### 4.2 Envoy 预编译包来源

```makefile
# Makefile.core.mk 中的默认值
ENVOY_PACKAGE_URL_PATTERN = https://github.com/higress-group/proxy/releases/download/v2.1.11/envoy-symbol-ARCH.tar.gz
```

其中 `ARCH` 在构建时被替换为 `amd64` 或 `arm64`。

### 4.3 内部调用链

```
make build-gateway-local  (Makefile.core.mk)
  │
  ├── 1. prebuild（同上）
  │
  ├── 2. build-golang-filter
  │     └── tools/hack/build-golang-filters.sh
  │           cd plugins/golang-filter
  │           GOARCH=${TARGET_ARCH} make build
  │           cp golang-filter_${TARGET_ARCH}.so → external/package/
  │
  └── 3. tools/hack/build-istio-image.sh docker
        │  cd external/istio
        │  设置 ISTIO_ENVOY_LINUX_RELEASE_URL（Envoy 下载地址）
        │  挂载 external/package → /home/package
        │
        └── 在构建容器中执行 istio 的 make docker
              ├── 下载 Envoy tar.gz 并解压
              └── docker build -f Dockerfile.proxyv2 ...
```

### 4.4 proxyv2 镜像内容

最终的 `docker.proxyv2` 镜像（即 Higress Gateway）包含：

```
/usr/local/bin/envoy                          ← Envoy 二进制
/usr/local/bin/pilot-agent                    ← Pilot Agent（管理 Envoy 生命周期）
/var/lib/istio/envoy/golang-filter.so         ← Golang Filter 动态库（MCP Server 等）
/var/lib/istio/envoy/envoy_bootstrap_tmpl.json ← Envoy 启动配置模板
/usr/local/bin/higress-proxy-start.sh         ← 容器入口脚本
```

## 5. 代码修改后的合入流程

本地编译验证通过后，修改需要合入到对应的上游仓库：

```
修改 envoy/envoy 中的代码
  → 提交到 higress-group/envoy 仓库
  → 更新 istio/proxy WORKSPACE 中的 ENVOY_SHA 指向新 commit
  → 提交到 istio/proxy 仓库
  → 在 higress 主仓库中更新 submodule 引用
  → CI 构建新的 Envoy 产物并发布到 GitHub Releases
  → 更新 Makefile.core.mk 中的 ENVOY_PACKAGE_URL_PATTERN 指向新版本
```

涉及的仓库和对应修改：

| 步骤 | 仓库 | 修改内容 |
|------|------|----------|
| 1 | higress-group/envoy | Envoy 核心代码或扩展代码 |
| 2 | istio/proxy | `WORKSPACE` 中的 `ENVOY_SHA`；如新增扩展还需修改 `extensions_build_config.bzl` |
| 3 | higress 主仓库 | 更新 submodule 指针（`git submodule update`） |
| 4 | higress 主仓库 | `Makefile.core.mk` 中的 `ENVOY_PACKAGE_URL_PATTERN` 版本号 |

## 6. 构建环境

| 组件 | 版本 / 配置 |
|------|------------|
| 构建镜像 | `higress/build-tools-proxy:release-1.19-...` |
| 编译器 | clang / clang++ |
| 构建系统 | Bazel |
| Envoy 基线 | 1.27（higress-group/envoy fork） |
| 目标架构 | amd64 / arm64 |

## 7. 构建全景图

```
                          make build-envoy
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
              git submodule            prebuild.sh
              update --init            拷贝到 external/
                    │                       │
                    ▼                       ▼
            ┌───────────────────────────────────────┐
            │         构建容器 (build-tools-proxy)    │
            │                                        │
            │  工作目录  = external/proxy             │
            │  /home/envoy = external/envoy          │
            │  /home/package = external/package      │
            │                                        │
            │  Bazel 编译:                            │
            │  ┌──────────────────────────────────┐  │
            │  │ istio/proxy (WORKSPACE 入口)      │  │
            │  │   ├── @envoy (envoy/envoy 源码)  │  │
            │  │   ├── extensions/ (Istio 扩展)    │  │
            │  │   └── extension_config.bzl       │  │
            │  │       (扩展注册表)                  │  │
            │  └──────────┬───────────────────────┘  │
            │             ▼                          │
            │    /home/package/envoy-*.tar.gz        │
            └─────────────┬──────────────────────────┘
                          │
                          ▼ 上传到文件服务器
                          │
                          ▼ 设置 ENVOY_PACKAGE_URL_PATTERN
                          │
                  make build-gateway-local
                          │
              ┌───────────┼────────────┐
              ▼           ▼            ▼
         下载/使用     编译 Golang    编译 pilot-agent
         Envoy 产物   Filter .so     (istio/istio)
              │           │            │
              └───────────┴────────────┘
                          │
                          ▼
                 docker.proxyv2 镜像
              ┌───────────────────────────┐
              │ /usr/local/bin/envoy      │
              │ golang-filter.so         │
              │ pilot-agent              │
              │ envoy_bootstrap_tmpl.json │
              └───────────────────────────┘
```
