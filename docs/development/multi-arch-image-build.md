# 多架构镜像构建与推送指南

## 背景

项目需要同时支持 amd64 和 arm64 架构的部署环境。通过 Docker Manifest List（Fat Manifest）机制，可以让同一个 tag 自动适配不同架构的节点。

---

## Manifest 多架构原理

### 三层结构

```
Registry Tag (e.g. higress:2.1.12)
    │
    ▼
┌─────────────────────────────────┐
│  Manifest List (Fat Manifest)   │  ← 一个 JSON，列出所有架构的 manifest
│  mediaType: manifest.list.v2    │
│  digest: sha256:d40d56...       │
├─────────────────────────────────┤
│  manifests:                     │
│    - platform: linux/amd64      │
│      digest: sha256:e39a1e...   │──→ 指向 amd64 的 Image Manifest
│    - platform: linux/arm64      │
│      digest: sha256:b77ac8...   │──→ 指向 arm64 的 Image Manifest
└─────────────────────────────────┘

┌─────────────────────────────────┐
│  Image Manifest (per-arch)      │  ← 描述单个架构的 layers + config
│  mediaType: manifest.v2         │
│  digest: sha256:e39a1e...       │
├─────────────────────────────────┤
│  config:                        │
│    digest: sha256:182ac8...     │──→ Image Config（docker inspect 的 Id）
│  layers:                        │
│    - sha256:3153aa...           │──→ 各层 tar.gz
│    - sha256:54caf5...           │
└─────────────────────────────────┘

┌─────────────────────────────────┐
│  Image Config                   │  ← 包含架构、环境变量、CMD 等元数据
│  digest: sha256:182ac8...       │  ← docker inspect 看到的 Image ID
└─────────────────────────────────┘
```

### 拉取流程

1. Client 请求 `GET /v2/<repo>/manifests/<tag>`
2. Registry 返回 Manifest List
3. Client 根据自己的 `os/architecture` 从 manifests 数组中选择对应的 digest
4. Client 请求对应架构的 Image Manifest
5. Client 按 layers 逐层下载 blob

### Digest 对照关系

同一个镜像有多个 digest，容易混淆：

| 名称 | 来源 | 示例 |
|------|------|------|
| Manifest List Digest | `docker manifest push` 返回 | `sha256:d40d56...` |
| Image Manifest Digest | `docker push image:tag-amd64` 返回 | `sha256:e39a1e...` |
| Image Config ID | `docker inspect --format '{{.Id}}'` | `sha256:182ac8...` |

验证时用 Image Config ID 对比最可靠——两端 `docker inspect` 的 Id 一致就说明是同一个镜像。

---

## 推送方式

### 方式一：buildx 一步到位（推荐日常开发）

```bash
# 前提：准备好各架构的 binary
GOOS=linux GOARCH=amd64 go build -o out/docker/amd64/higress ./cmd/higress
GOOS=linux GOARCH=arm64 go build -o out/docker/arm64/higress ./cmd/higress

# 构建并推送多架构镜像
docker buildx build --platform linux/amd64,linux/arm64 \
  -t registry.cn-shanghai.aliyuncs.com/daofeng/higress:2.1.12 \
  -f out/docker/Dockerfile.patch out/docker/ \
  --push
```

优点：一步完成，不会有覆盖问题。
缺点：推送后本地没有可用的镜像（buildx 直接推到 registry）。

### 方式二：手动 manifest（需要精确控制时使用）

```bash
# Step 1: 分别构建各架构镜像
docker build --platform linux/amd64 --no-cache \
  -t registry.cn-shanghai.aliyuncs.com/daofeng/higress:2.1.12-amd64 \
  -f out/docker/Dockerfile.patch out/docker/

docker build --platform linux/arm64 --no-cache \
  -t registry.cn-shanghai.aliyuncs.com/daofeng/higress:2.1.12-arm64 \
  -f out/docker/Dockerfile.patch out/docker/

# Step 2: 分别推送各架构（用带后缀的 tag）
docker push registry.cn-shanghai.aliyuncs.com/daofeng/higress:2.1.12-amd64
docker push registry.cn-shanghai.aliyuncs.com/daofeng/higress:2.1.12-arm64

# Step 3: 创建 manifest list
docker manifest create registry.cn-shanghai.aliyuncs.com/daofeng/higress:2.1.12 \
  registry.cn-shanghai.aliyuncs.com/daofeng/higress:2.1.12-amd64 \
  registry.cn-shanghai.aliyuncs.com/daofeng/higress:2.1.12-arm64

# Step 4: 推送 manifest list
docker manifest push registry.cn-shanghai.aliyuncs.com/daofeng/higress:2.1.12
```

### 验证

```bash
# 查看远程 manifest list 内容
docker manifest inspect registry.cn-shanghai.aliyuncs.com/daofeng/higress:2.1.12

# 在目标机器上拉取并确认 Image ID
docker pull registry.cn-shanghai.aliyuncs.com/daofeng/higress:2.1.12
docker inspect registry.cn-shanghai.aliyuncs.com/daofeng/higress:2.1.12 --format '{{.Id}}'
```

---

## 踩坑记录

### 问题：`docker push` 覆盖 manifest list

**现象**：用 `docker buildx --push` 推送了多架构 manifest list 后，又用 `docker push image:tag` 推送了单架构镜像，导致 tag 从 manifest list 降级为单架构 manifest，arm64 节点拉取时拿到了 amd64 镜像。

**原因**：
- `docker push image:tag` 推送的是单架构 Image Manifest（`manifest.v2`）
- Registry 对同一个 tag 只存一个 manifest，后推的覆盖先推的
- `docker push` 单架构镜像会把 tag 从 manifest list 降级为单架构 manifest

**规则**：
> ⚠️ **绝对不要对多架构 tag 执行 `docker push image:tag`（单架构推送），否则会覆盖 manifest list。**

如果需要更新某个架构的镜像，正确做法是：
1. 推送到带架构后缀的 tag（如 `2.1.12-amd64`）
2. 重新创建并推送 manifest list

### 问题：本地镜像缓存干扰 manifest inspect

**现象**：`docker manifest inspect image:tag` 显示的是本地缓存的单架构 manifest，而非远程的 manifest list。

**解决**：
```bash
# 删除本地同名镜像和 manifest 缓存
docker rmi image:tag 2>/dev/null
docker manifest rm image:tag 2>/dev/null
# 然后再 inspect
docker manifest inspect image:tag
```

### 问题：K8s 节点 imagePullPolicy: IfNotPresent 导致不拉新镜像

**现象**：推送了新镜像但 Pod 仍然用旧的。

**解决**：
```bash
# 改为 Always
kubectl patch deploy <name> -n <ns> --type='json' \
  -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"Always"}]'

# 或者在节点上手动删除旧镜像
crictl rmi <image:tag>
# 然后重启 Pod
kubectl rollout restart deployment/<name> -n <ns>
```

---

## Dockerfile 参考

```dockerfile
# Dockerfile.patch - 基于基础镜像替换 binary
FROM registry.cn-shanghai.aliyuncs.com/daofeng/higress:2.1.11
ARG TARGETARCH
COPY ${TARGETARCH}/higress /usr/local/bin/higress
```

`TARGETARCH` 由 `--platform` 参数自动设置（`amd64` 或 `arm64`），对应 build context 中的目录结构：
```
out/docker/
├── amd64/higress    # GOOS=linux GOARCH=amd64 编译产物
├── arm64/higress    # GOOS=linux GOARCH=arm64 编译产物
└── Dockerfile.patch
```
