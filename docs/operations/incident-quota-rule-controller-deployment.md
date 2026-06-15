# 故障记录：QuotaRule Controller 部署导致 404

## 时间

2026-06-09

## 现象

ls-test namespace 下所有路由返回 404。

## 根因

部署 QuotaRule Controller 时替换了 higress-controller 的 discovery 容器镜像（`pilot:quota-rule`），导致 gateway 无法向 controller 认证（`Unauthenticated`），拿不到 xDS 配置。

具体原因链：

1. **`pilot:quota-rule` 镜像是从 `gateway:2.1.12` 基础镜像构建的**（错误的 base），第一次修复后改为 `pilot:2.1.12` 基础镜像
2. **修改了 `CLUSTER_ID` 环境变量从 `Kubernetes` 改为 `kubernetes`**（小写），为了解决 ConfigMap 命名不合法的问题。虽然认证失败的直接原因还需进一步确认，但修改 CLUSTER_ID 可能影响了集群身份识别
3. **gateway 与 controller 之间通过 mTLS/JWT 认证**，controller 的 identity 变化可能导致认证链断裂

## 恢复步骤

```bash
# 1. 回滚 controller 镜像
kubectl set image deploy/higress-controller -n ls-test \
  discovery=registry.cn-shanghai.aliyuncs.com/daofeng/pilot:2.1.12

# 2. 移除手动添加的环境变量
kubectl set env deploy/higress-controller -n ls-test -c discovery \
  WATCH_RESOURCES_BY_NAMESPACE_FOR_PRIMARY_CLUSTER- \
  CLUSTER_ID=Kubernetes

# 3. 重启
kubectl rollout restart deploy higress-controller -n ls-test

# 4. 等 gateway 重连（可能需要重启 gateway）
kubectl rollout restart deploy higress-gateway -n ls-test
```

## 教训

1. **不要直接替换生产环境的 controller 镜像做测试** — controller 挂了整个网关的路由全断
2. **不要随意修改 CLUSTER_ID 等身份相关的环境变量** — 影响 mTLS 认证链
3. **测试新 controller 应该用独立的 deployment**，不影响现有网关实例
4. **ConfigMap 命名不合法（大写 `Kubernetes`）应该在代码中做 `strings.ToLower` 处理**，而不是改环境变量

## 后续改进

- QuotaRule Controller 中 ConfigMap 名称生成逻辑应该自动转小写（`strings.ToLower(features.ClusterName)`）
- 部署测试时使用独立的 controller deployment，不替换现有实例
