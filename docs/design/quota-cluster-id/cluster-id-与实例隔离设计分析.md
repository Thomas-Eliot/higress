# cluster-id 与实例隔离设计分析

> 记录时间：2026-06-16。基于对 `external/istio`（go.mod `replace istio.io/istio => ./external/istio`，实际构建源）与 `pkg/` 的代码核对 + `ls-test` 在跑实例的实测。
>
> 触发问题：多个 Higress 实例共享同一 K8s 集群，希望按实例隔离配额（Redis quota domain）。自然想法是「cluster_id = instanceid」，但发现 `--clusterID` arg 与 `CLUSTER_ID` env 行为割裂，遂从设计角度梳理「合理的配置应该如何」。

---

## 决策（2026-06-16）

> **不再用 cluster-id 承载实例身份。** 三种身份按下表处置：
>
> | 身份 | 决策 |
> |---|---|
> | 物理集群身份（①） | **固定 `Kubernetes`**，所有实例相同 |
> | 信任配对（③） | **固定 `Kubernetes`**，控制器 `--clusterID` / env 与网关 `ISTIO_META_CLUSTER_ID` 全留默认即一致 |
> | **实例身份（②）** | **独立为 QuotaRule CR 的 `key_domain` 配置**，每实例唯一，仅用于 Redis quota 隔离 |
>
> 收益：cluster-id 全程默认，零额外配置、零 blast radius（不碰 auth/registry/SDS/CA-cert）；加实例只声明一个 `key_domain`。下文第六、七节据此细化。

---

## 一、病根：一个 `cluster-id` 承载了三种身份

| 身份 | 用途 | 唯一性要求 | 变更频率 |
|---|---|---|---|
| **物理集群身份** | istio 多集群联邦（EDS / network 归属） | 同一 K8s 集群内**所有实例应相同** | 几乎不变 |
| **实例身份** | quota Redis domain 隔离、可观测 | **每实例唯一** | 每实例一个 |
| **控制面↔数据面信任配对** | JWT 鉴权 `getKubeClient` | **实例内一致**即可，跨实例可不唯一 | 跟随实例 |

三者语义不同、唯一性要求**互相矛盾**（第一个要「相同」，第二个要「唯一」），却被迫共用一个 `cluster-id` 名字，还散在 **3 个不同步的旋钮**上。把「要唯一」的实例身份去覆盖「要相同」的集群身份——冲突的根在这里，而不在某个配置项。

### 三个旋钮（代码出处）

| 旋钮 | 来源 | 驱动什么 | 代码 |
|---|---|---|---|
| `features.ClusterName` | **higress 容器 `CLUSTER_ID` env** | quota ConfigMap 名 + Redis domain；SDS secret 命名 / CRName / leader 选举 / CA-cert configmap 名 / `shouldWatchServices` | `external/istio/pilot/pkg/features/pilot.go:348` |
| `KubeOptions.ClusterID` | **higress 容器 `--clusterID` arg** | kube 服务注册中心 cluster ID + JWT 鉴权 `a.clusterID` | `pkg/cmd/server.go:121` |
| 网关身份 | **gateway 容器 `ISTIO_META_CLUSTER_ID`** | 上报 `clusterid` header（鉴权）+ EDS 归属 | `helm/core/templates/_pod.tpl:118` |

---

## 二、`--clusterID` arg 与 `CLUSTER_ID` env 的真实关系（关键纠错）

直觉上「flag 优先于 env，两者初始化同一个值」——但代码里其实是**两个独立 global**，该直觉只对其中一个成立。

```go
// 变量①：features.ClusterName —— 只认 env，全程不被 flag 回写
features.ClusterName = env.Register("CLUSTER_ID", "Kubernetes")   // pilot/pkg/features/pilot.go:348

// 变量②：KubeOptions.ClusterID —— 认 flag
//   上游 istio（external/istio/pilot/cmd/pilot-discovery/app/cmd.go:152）：
//     StringVar(&KubeOptions.ClusterID, "clusterID", features.ClusterName, ...)  // 默认“播种”自 env
//   higress（pkg/cmd/server.go:121）：
//     StringVar(&KubeOptions.ClusterID, "clusterID", "Kubernetes", ...)          // 默认写死字面量，不读 env
```

全仓 grep 确认：**没有任何一处把 flag 回写进 `features.ClusterName`**（`features.ClusterName =` 只出现在 `env.Register` 那一行），也无 `os.Setenv("CLUSTER_ID", …)`。

| 消费方 | 读哪个变量 | flag 能否覆盖 |
|---|---|---|
| quota ConfigMap 名 / Redis domain / SDS 名 / CRName / leader 选举 / CA-cert / `shouldWatchServices` | **`features.ClusterName`（env）** | **不能，永远只看 env** |
| kube 服务注册中心 cluster ID / JWT 鉴权 | `KubeOptions.ClusterID`（flag） | 能，flag > env |

**结论**：
- 「flag 优先于 env」只对变量②成立（上游把 flag 默认播种成 env 值，不传 flag 就 = env，传了覆盖）。
- 变量①（quota 命名等）**从头到尾只认 env**，即便上游、即便显式传 `--clusterID=foo`，quota 命名也不变。
- 能一处贯穿全部的是 **env**，不是 flag。
- higress 把 flag 默认硬编码成 `"Kubernetes"`（而非上游的 `features.ClusterName`），**破坏了「env 播种 flag」**，是导致两者脱钩的实现疏忽——平时两边都默认 `Kubernetes` 看不出来，设非默认值才暴露。

---

## 三、原始设计意图：cluster-id = `gw-<instanceid>-istio`

内部版本的 cluster-id **本就是每实例唯一标识**，约定格式带 `-istio` 后缀，所有命名派生都围绕它自动成立：

- 证据 1：`docs/design/plugin-sharding/插件配置分片设计.md` 里 WasmPlugin label `istio/cluster-id: gw-xxxxxx-istio`。
- 证据 2：quota 派生逻辑天然吃这个后缀（`external/istio/.../quotarule/quotarule.go`）：
  - endpoints 名 `GetEndpointsName()` = `strings.Replace(ClusterName, "istio", "envoy-hs", 1)` → `gw-xxxxxx-istio` ⇒ `gw-xxxxxx-envoy-hs`（headless Service）
  - 实例名 `getInstanceName()` = `TrimSuffix(ClusterName, "-istio")` → `gw-xxxxxx` ⇒ domain `gw-xxxxxx-quotarule`
- 证据 3：单测断言 `GetEndpointsName() == "quotarule-cluster-envoy-hs"`（features.ClusterName=`quotarule-cluster-istio`），`controller_test.go` / `TestGetEndpointsName`。

**所以「用 cluster-id 当 instanceid」其实符合原始设计**。割裂来自两处开源化偏差：
1. 开源默认 cluster-id = `Kubernetes`（无 `-istio`）⇒ `Replace("Kubernetes","istio","envoy-hs")` 原样返回 `Kubernetes` ⇒ endpoints 名错 ⇒ 必须用 `QUOTA_GATEWAY_ENDPOINTS_NAME=envoy-hs` 兜底。
2. higress `serve` 把 `--clusterID` 默认硬编码 `Kubernetes`（脱钩，见第二节）。

---

## 四、鉴权 / EDS 的耦合（为什么不能随便只改一处）

- **JWT 鉴权**：网关 pilot-agent 连 higress-controller xDS/CA（`:15012`/`:15010`）时把自己的 `ISTIO_META_CLUSTER_ID` 当 `clusterid` header 上送；`getKubeClient` 要求 `控制器 --clusterID(a.clusterID) == 该 header`，否则因 higress 的 `remoteKubeClientGetter==nil` 返回 nil ⇒ 鉴权失败「could not get cluster X's kube client」⇒ 网关拿不到任何配置（`external/istio/security/pkg/server/ca/authenticate/kubeauth/kube_jwt.go:117-187`）。
- **改 `features.ClusterName`（env）的 blast radius**：除 quota 外还波及 SDS secret 命名（`credentials/ali_resource.go`）、CRName（`model/ali_push_context.go:137`）、leader 选举锁名、CA-cert configmap 名（`namespacecontroller.go`，`!= "Kubernetes"` 时改名）、`shouldWatchServices`（`multicluster.go:158`，仅 label-watch 模式生效——`ls-test` 当前未开）。
- 实测 `ls-test`（在跑的栈）：higress 容器**无 `--clusterID` arg**、`CLUSTER_ID=Kubernetes`；网关 `ISTIO_META_CLUSTER_ID=Kubernetes` ⇒ 两侧缺省天然匹配，鉴权正常。`gateway` xDS 连的是 **higress 容器**（不是 discovery），故 quota/路由不依赖 discovery 容器的 cluster id。

---

## 五、设计原则

1. **单一事实源**：同一身份只配置一次，其余 derive，绝不让运维在 controller env、controller flag、gateway meta 三处手敲同一值还得自己保证一致。
2. **关注点分离**：quota 隔离是 quota 的局部问题，不该拖动 auth / registry / SDS / CA-cert 这些集群身份语义。

---

## 六、采纳的设计（分层，常见场景零配置）

核心判断：**真正需要每实例唯一的，只有 Redis quota domain。** ConfigMap 靠 namespace 已隔离；auth/registry 只需实例内一致。所以不该为了 quota 去动 cluster-id。

### ① 实例身份 → QuotaRule CR `redis_info.key_domain`（本决策核心）

**QuotaRule CR 的 `redis_info` 加可选 `key_domain` 字段**，作为 Redis bucket key 的 domain 段：
- 语义：Redis key 形如 `rl_dc:<key_domain>:cu_*`。`key_domain` **直接给出整个 domain 字符串**（不再走 `getInstanceName()` 派生）。
- 默认（未填）= 现状 `<instanceName>-quotarule`（向后兼容，现网不动）。
- 多实例：由**控制台填 `key_domain` = instanceid**（每实例唯一）。
- 为什么放 CR 最优：控制台既建 CR、又往 Redis 写 key，domain 声明在 CR 里 ⇒ 数据面（controller 下发的 bucket config）与写入方（控制台 HSET）读**同一处声明** ⇒ 杜绝「两边各自推导、大小写/前缀对不上」。
- ⚠️ 仍受 Redis key 取值约束：`key_domain` 原样进 key，控制台写入与 CR 声明须**大小写一致**。

### ② 集群身份 + 信任配对 → 固定 `Kubernetes`，不动

- cluster-id 三个旋钮（controller `CLUSTER_ID` env、controller `--clusterID` arg、gateway `ISTIO_META_CLUSTER_ID`）**全留默认 `Kubernetes`**，天然一致，JWT 鉴权 / EDS 正常。
- 因为不再设非默认值，第二节那个「flag 默认硬编码、与 env 脱钩」的疏忽**在本决策下不触发**，无需修（仅作未来真多集群联邦时的备忘）。

这样 quota 隔离 ⟂ 集群身份，互不拖累：加实例只声明一个 `key_domain`，根本不碰 cluster-id。

---

## 七、落地改动点

### 核心：QuotaRule CR `redis_info.key_domain`

1. **proto / CRD**：`redis_info` 增加 `string key_domain`（optional）。改 istio_api 的 QuotaRule proto + 重生成 pb.go、CRD schema、typed client。
2. **controller 下发**：domain 派生改为「`key_domain` 非空则用之，否则回落 `getInstanceName()+"-quotarule"`」。改点在 `external/istio/.../quotarule/quotarule.go` 现有三处 `strings.Join([]string{getInstanceName(), DomainPostfix}, …)`（`:778, :1677, :1856`）——抽一个 `resolveDomain(rule)` 统一。注意 domain 同时进 ① 生成的 ratelimit ConfigMap、② envoy RLQS filter，两处必须用同一值（本就同源，保持即可）。
3. **控制台对齐**：控制台建 CR 时填 `key_domain = instanceid`，并用**同一字符串**写 Redis（`rl_dc:<key_domain>:cu_*`、`rl_dc:<key_domain>:cu_<id>` 动态配额）。

### 不在本决策范围（cluster-id 保持默认，无需做）

- ~~修 `pkg/cmd/server.go:121` flag 默认~~：本决策不设非默认 cluster-id，不触发脱钩，无需改。
- ~~helm cluster-id 单源~~：同理，三旋钮全默认，不必收敛。
- 二者仅在未来「真接入多集群联邦」时才需要，届时再议。

---

## 附：本次核对的关键代码出处

| 事实 | 出处 |
|---|---|
| `features.ClusterName` = `CLUSTER_ID` env，默认 `Kubernetes` | `external/istio/pilot/pkg/features/pilot.go:348` |
| `--clusterID` 默认（上游）= `features.ClusterName` | `external/istio/pilot/cmd/pilot-discovery/app/cmd.go:152` |
| `--clusterID` 默认（higress）= 硬编码 `"Kubernetes"` | `pkg/cmd/server.go:121` |
| quota ConfigMap 名 = `ToLower(ClusterName+"-ratelimit-config")` | `external/istio/.../quotarule/quotarule.go:1824` 等 |
| Redis domain = `TrimSuffix(ClusterName,"-istio")+"-quotarule"` | `quotarule.go:64-68, 778` |
| endpoints 名 fallback = `Replace(ClusterName,"istio","envoy-hs",1)` | `quotarule.go:54-63` |
| length-0 不下发 | `quotarule.go:250-253`，`GetEnvoyEndpointLen()` `:1799` |
| JWT 鉴权 `getKubeClient` 需 flag == 网关 header | `external/istio/security/pkg/server/ca/authenticate/kubeauth/kube_jwt.go:117-187` |
| JWT authenticator 用 `--clusterID` | `pkg/bootstrap/server.go:396` |
| `shouldWatchServices` 比较 `clusterID == features.ClusterName` | `external/istio/pilot/pkg/serviceregistry/kube/controller/multicluster.go:152-166` |
| CRName 用 `features.ClusterName` | `external/istio/pilot/pkg/model/ali_push_context.go:137-138` |
| SDS secret 资源名用 `features.ClusterName` | `external/istio/pilot/pkg/model/credentials/ali_resource.go:20-26` |

相关运维 runbook：[`docs/testing/quota-rule/e2e-quota-rule-env-setup.md`](../../testing/quota-rule/e2e-quota-rule-env-setup.md) §2「为什么」（已据本分析改正归因）。
