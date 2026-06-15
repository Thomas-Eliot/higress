#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NGINX Ingress to Higress 迁移分析工具 v2

基于 annotation-compatibility.md 和 migration-guide.md 的最新兼容性分析数据。

功能：
1. 扫描K8s集群中所有NGINX Ingress资源
2. 分析使用的注解兼容性（130个注解，5种兼容性分类）
3. 生成详细的迁移评估报告（HTML/JSON）
4. 输出平滑迁移的风险等级和建议

兼容性分类：
  ✅ 完全兼容 (41个) - Higress 原生支持
  🔵 可等价替换 (37个) - 通过插件/配置实现
  ❌ 不兼容 (34个) - 架构差异导致功能缺失
  ⚠️ 部分兼容 (7个) - 语义不完全一致
  🔴 无需迁移 (11个) - Envoy 天然覆盖或已过时

使用方法：
    python nginx_ingress_migration_analyzer.py [--kubeconfig ~/.kube/config] [--output report.html]
"""

import json
import sys
import argparse
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple

import subprocess


# ============================================================================
# 注解兼容性分类定义（基于 annotation-compatibility.md v2）
# 共 130 个注解，按 5 种兼容性分类
# ============================================================================

ANNOTATION_COMPATIBILITY = {
    # ✅ 完全兼容 (41个)
    "✅ 完全兼容": {
        # 1. 路由与重写 (4个)
        "nginx.ingress.kubernetes.io/rewrite-target": {
            "category": "路由与重写",
            "priority": "重要且常用",
            "solution": "直接使用原注解或 higress.io/rewrite-target",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/use-regex": {
            "category": "路由与重写",
            "priority": "重要且常用",
            "solution": "直接使用原注解或 higress.io/use-regex。⚠️ 路由优先级差异：NGINX 中 regex > prefix，Higress 中 prefix > regex，需检查是否存在 regex 路径与 prefix 路径的优先级冲突",
            "risk": "中风险，路由优先级差异可能导致流量路由到不同后端"
        },
        "nginx.ingress.kubernetes.io/upstream-vhost": {
            "category": "路由与重写",
            "priority": "重要但不常用",
            "solution": "直接使用原注解或 higress.io/upstream-vhost",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/app-root": {
            "category": "路由与重写",
            "priority": "不重要但常用",
            "solution": "直接使用原注解或 higress.io/app-root",
            "risk": "无风险"
        },
        # 2. 重定向 (5个)
        "nginx.ingress.kubernetes.io/ssl-redirect": {
            "category": "重定向",
            "priority": "重要且常用",
            "solution": "直接使用原注解或 higress.io/ssl-redirect",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/force-ssl-redirect": {
            "category": "重定向",
            "priority": "重要但不常用",
            "solution": "直接使用原注解或 higress.io/force-ssl-redirect",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/permanent-redirect": {
            "category": "重定向",
            "priority": "不重要但常用",
            "solution": "直接使用原注解或 higress.io/permanent-redirect",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/permanent-redirect-code": {
            "category": "重定向",
            "priority": "不重要且不常用",
            "solution": "直接使用原注解或 higress.io/permanent-redirect-code",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/temporal-redirect": {
            "category": "重定向",
            "priority": "不重要但常用",
            "solution": "直接使用原注解或 higress.io/temporal-redirect",
            "risk": "无风险"
        },
        # 3. CORS (7个)
        "nginx.ingress.kubernetes.io/enable-cors": {
            "category": "CORS",
            "priority": "重要且常用",
            "solution": "直接使用原注解或 higress.io/enable-cors",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/cors-allow-origin": {
            "category": "CORS",
            "priority": "重要且常用",
            "solution": "直接使用原注解或 higress.io/cors-allow-origin",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/cors-allow-methods": {
            "category": "CORS",
            "priority": "重要且常用",
            "solution": "直接使用原注解或 higress.io/cors-allow-methods",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/cors-allow-headers": {
            "category": "CORS",
            "priority": "重要且常用",
            "solution": "直接使用原注解或 higress.io/cors-allow-headers",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/cors-allow-credentials": {
            "category": "CORS",
            "priority": "重要但不常用",
            "solution": "直接使用原注解或 higress.io/cors-allow-credentials",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/cors-expose-headers": {
            "category": "CORS",
            "priority": "不重要但常用",
            "solution": "直接使用原注解或 higress.io/cors-expose-headers",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/cors-max-age": {
            "category": "CORS",
            "priority": "不重要但常用",
            "solution": "直接使用原注解或 higress.io/cors-max-age",
            "risk": "无风险"
        },
        # 4. 灰度发布 (8个)
        "nginx.ingress.kubernetes.io/canary": {
            "category": "灰度发布",
            "priority": "重要且常用",
            "solution": "直接使用原注解或 higress.io/canary",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/canary-weight": {
            "category": "灰度发布",
            "priority": "重要且常用",
            "solution": "直接使用原注解或 higress.io/canary-weight",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/canary-by-header": {
            "category": "灰度发布",
            "priority": "重要且常用",
            "solution": "直接使用原注解或 higress.io/canary-by-header",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/canary-by-header-value": {
            "category": "灰度发布",
            "priority": "重要且常用",
            "solution": "直接使用原注解或 higress.io/canary-by-header-value",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/canary-by-header-pattern": {
            "category": "灰度发布",
            "priority": "重要但不常用",
            "solution": "直接使用原注解或 higress.io/canary-by-header-pattern",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/canary-by-cookie": {
            "category": "灰度发布",
            "priority": "重要但不常用",
            "solution": "直接使用原注解或 higress.io/canary-by-cookie",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/canary-weight-total": {
            "category": "灰度发布",
            "priority": "不重要且不常用",
            "solution": "Higress 支持金丝雀总权重配置",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/affinity-canary-behavior": {
            "category": "灰度发布",
            "priority": "不重要且不常用",
            "solution": "Higress 源码中已定义此注解(loadbalance.go)，行为始终为 legacy",
            "risk": "无风险"
        },
        # 5. 负载均衡与会话保持 (6个)
        "nginx.ingress.kubernetes.io/affinity": {
            "category": "负载均衡",
            "priority": "重要且常用",
            "solution": "直接使用原注解或 higress.io/affinity",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/session-cookie-name": {
            "category": "负载均衡",
            "priority": "不重要但常用",
            "solution": "已在 loadbalance.go 验证",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/session-cookie-path": {
            "category": "负载均衡",
            "priority": "不重要但常用",
            "solution": "已在 loadbalance.go 验证",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/session-cookie-max-age": {
            "category": "负载均衡",
            "priority": "不重要但常用",
            "solution": "已在 loadbalance.go 验证",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/session-cookie-expires": {
            "category": "负载均衡",
            "priority": "不重要且不常用",
            "solution": "已在 loadbalance.go 验证",
            "risk": "无风险"
        },
        # 6. 访问控制 (1个)
        "nginx.ingress.kubernetes.io/whitelist-source-range": {
            "category": "访问控制",
            "priority": "重要且常用",
            "solution": "直接使用原注解或 higress.io/whitelist-source-range",
            "risk": "无风险"
        },
        # 7. SSL/TLS (4个)
        "nginx.ingress.kubernetes.io/proxy-ssl-secret": {
            "category": "SSL/TLS",
            "priority": "重要但不常用",
            "solution": "直接使用原注解或 higress.io/proxy-ssl-secret",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/proxy-ssl-name": {
            "category": "SSL/TLS",
            "priority": "重要但不常用",
            "solution": "Higress 支持后端 TLS SNI 名称",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/proxy-ssl-server-name": {
            "category": "SSL/TLS",
            "priority": "不重要但常用",
            "solution": "Higress 支持是否在后端 TLS 握手中发送 SNI",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/proxy-ssl-verify": {
            "category": "SSL/TLS",
            "priority": "重要但不常用",
            "solution": "直接使用原注解或 higress.io/proxy-ssl-verify",
            "risk": "无风险"
        },
        # 8. 后端服务配置 (4个)
        "nginx.ingress.kubernetes.io/proxy-next-upstream": {
            "category": "后端服务配置",
            "priority": "重要且常用",
            "solution": "Higress 支持重试条件配置",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/proxy-next-upstream-timeout": {
            "category": "后端服务配置",
            "priority": "重要且常用",
            "solution": "Higress 支持重试超时配置",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/proxy-next-upstream-tries": {
            "category": "后端服务配置",
            "priority": "重要且常用",
            "solution": "直接使用原注解或 higress.io/proxy-next-upstream-tries",
            "risk": "无风险"
        },
        # 9. 错误处理 (2个)
        "nginx.ingress.kubernetes.io/custom-http-errors": {
            "category": "错误处理",
            "priority": "重要但不常用",
            "solution": "直接使用原注解（已在 default_backend.go 验证）",
            "risk": "无风险"
        },
        "nginx.ingress.kubernetes.io/default-backend": {
            "category": "错误处理",
            "priority": "重要但不常用",
            "solution": "Higress 支持指定默认后端服务",
            "risk": "无风险"
        },
    },

    # 🔵 可等价替换 (37个)
    "🔵 可等价替换": {
        # 路由与重写 (4个)
        "nginx.ingress.kubernetes.io/preserve-trailing-slash": {
            "category": "路由与重写",
            "priority": "不重要且不常用",
            "solution": "通过 Ingress pathType: Exact 实现精确匹配",
            "risk": "低风险，需要调整 pathType 配置"
        },
        "nginx.ingress.kubernetes.io/proxy-redirect-from": {
            "category": "路由与重写",
            "priority": "不重要且不常用",
            "solution": "使用 WasmPlugin transformer，通过 respRules.replace 配合 path_pattern 正则匹配实现",
            "risk": "中风险，需要部署 transformer 插件"
        },
        "nginx.ingress.kubernetes.io/proxy-redirect-to": {
            "category": "路由与重写",
            "priority": "不重要且不常用",
            "solution": "使用 WasmPlugin transformer，通过 respRules.replace.newValue 设置新的 Location 值",
            "risk": "中风险，需要部署 transformer 插件"
        },
        "nginx.ingress.kubernetes.io/x-forwarded-prefix": {
            "category": "路由与重写",
            "priority": "不重要但常用",
            "solution": "通过 higress.io/request-header-control-add 实现",
            "risk": "低风险，需要添加请求头控制注解"
        },
        # 重定向 (1个)
        "nginx.ingress.kubernetes.io/from-to-www-redirect": {
            "category": "重定向",
            "priority": "不重要且不常用",
            "solution": "通过 higress.io/permanent-redirect 配合多 Ingress 规则实现",
            "risk": "低风险，需要创建额外的 Ingress 规则"
        },
        # 认证与授权 (10个)
        "nginx.ingress.kubernetes.io/auth-url": {
            "category": "认证与授权",
            "priority": "重要且常用",
            "solution": "需通过 ext-auth WASM 插件的 forward_auth 模式配置 WasmPlugin CRD 实现，不支持注解级透明迁移",
            "risk": "中风险，需要部署 ext-auth 插件并配置 WasmPlugin CRD"
        },
        "nginx.ingress.kubernetes.io/auth-response-headers": {
            "category": "认证与授权",
            "priority": "重要且常用",
            "solution": "需通过 ext-auth WASM 插件的 authorization_response.allowed_upstream_headers 配置实现",
            "risk": "中风险，需要部署 ext-auth 插件"
        },
        "nginx.ingress.kubernetes.io/auth-proxy-set-headers": {
            "category": "认证与授权",
            "priority": "重要但不常用",
            "solution": "需通过 ext-auth WASM 插件的 authorization_request.headers_to_add 配置实现",
            "risk": "低风险，需要使用 ext-auth 插件配置"
        },
        "nginx.ingress.kubernetes.io/auth-method": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "ext-auth WASM 插件 forward_auth 模式支持通过 endpoint.request_method 配置",
            "risk": "低风险，需要使用 ext-auth 插件配置"
        },
        "nginx.ingress.kubernetes.io/auth-type": {
            "category": "认证与授权",
            "priority": "不重要但常用",
            "solution": "通过 basic-auth WASM 插件实现（Higress v2.0.0+ 推荐），Digest 认证需自定义 WASM 插件",
            "risk": "中风险，需要迁移到 basic-auth 插件"
        },
        "nginx.ingress.kubernetes.io/auth-secret": {
            "category": "认证与授权",
            "priority": "不重要但常用",
            "solution": "迁移到 basic-auth WASM 插件后，用户凭证通过插件配置管理，不再依赖 K8s Secret",
            "risk": "中风险，需要迁移凭证管理方式"
        },
        "nginx.ingress.kubernetes.io/auth-secret-type": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "Higress v2.0.0+ 已移除 auth 注解解析，迁移到 basic-auth 插件后此概念不再适用",
            "risk": "低风险，无需等价替换"
        },
        "nginx.ingress.kubernetes.io/auth-realm": {
            "category": "认证与授权",
            "priority": "不重要但常用",
            "solution": "basic-auth WASM 插件 realm 硬编码为 MSE Gateway，不支持自定义",
            "risk": "低风险，realm 值不可自定义但不影响功能"
        },
        "nginx.ingress.kubernetes.io/auth-tls-verify-client": {
            "category": "认证与授权",
            "priority": "重要但不常用",
            "solution": "通过 higress.io/auth-tls-secret 配置 CA 证书实现 mTLS 验证，相当于 on",
            "risk": "低风险，配置 CA 证书即可"
        },
        "nginx.ingress.kubernetes.io/enable-global-auth": {
            "category": "认证与授权",
            "priority": "重要但不常用",
            "solution": "各认证插件均支持 global_auth 配置字段，可在域名/路由级别通过 allow 列表精细控制",
            "risk": "中风险，需要配置全局 WasmPlugin"
        },
        # mTLS 高级 (3个)
        "nginx.ingress.kubernetes.io/auth-tls-match-cn": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "通过 EnvoyFilter 配置 CertificateValidationContext 的 match_typed_subject_alt_names 实现 SAN 匹配",
            "risk": "中风险，Envoy 匹配 SAN 而非 CN，语义略有差异"
        },
        "nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "通过 EnvoyFilter 配置 forward_client_cert_details，使用 XFCC 头传递证书信息",
            "risk": "中风险，XFCC 头格式与 NGINX ssl-client-cert 不同，后端需适配"
        },
        "nginx.ingress.kubernetes.io/auth-tls-verify-depth": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "通过 EnvoyFilter 配置 CertificateValidationContext 的 max_verify_depth 字段实现",
            "risk": "低风险，Envoy 默认验证深度为 100"
        },
        # SSL/TLS (4个)
        "nginx.ingress.kubernetes.io/ssl-ciphers": {
            "category": "SSL/TLS",
            "priority": "重要但不常用",
            "solution": "通过 higress.io/ssl-cipher（单数）配置，功能等价但注解名称不同",
            "risk": "低风险，需要使用 Higress 注解"
        },
        "nginx.ingress.kubernetes.io/proxy-ssl-ciphers": {
            "category": "SSL/TLS",
            "priority": "不重要且不常用",
            "solution": "需通过 EnvoyFilter 配置 UpstreamTlsContext 的 cipher_suites 字段实现",
            "risk": "中风险，需要创建 EnvoyFilter"
        },
        "nginx.ingress.kubernetes.io/proxy-ssl-protocols": {
            "category": "SSL/TLS",
            "priority": "重要但不常用",
            "solution": "需通过 EnvoyFilter 配置 UpstreamTlsContext 的 tls_minimum/maximum_protocol_version 实现",
            "risk": "中风险，需要创建 EnvoyFilter"
        },
        "nginx.ingress.kubernetes.io/proxy-ssl-verify-depth": {
            "category": "SSL/TLS",
            "priority": "不重要且不常用",
            "solution": "通过 EnvoyFilter 配置 UpstreamTlsContext 的 max_verify_depth 字段实现",
            "risk": "低风险，Envoy 默认验证深度为 100"
        },
        # 限流与限速 (4个)
        "nginx.ingress.kubernetes.io/limit-rps": {
            "category": "限流与限速",
            "priority": "重要且常用",
            "solution": "使用 Higress key-rate-limit 插件，配置 limit_by_per_ip",
            "risk": "中风险，需要部署限流插件"
        },
        "nginx.ingress.kubernetes.io/limit-connections": {
            "category": "限流与限速",
            "priority": "重要但不常用",
            "solution": "推荐通过 EnvoyFilter connection_limit 限制下游并发连接数，或 DestinationRule maxConnections",
            "risk": "中风险，需要创建 EnvoyFilter 或 DestinationRule"
        },
        "nginx.ingress.kubernetes.io/limit-rpm": {
            "category": "限流与限速",
            "priority": "重要但不常用",
            "solution": "通过 key-rate-limit 插件配置等价的每分钟限流策略",
            "risk": "中风险，需要部署限流插件"
        },
        "nginx.ingress.kubernetes.io/limit-whitelist": {
            "category": "限流与限速",
            "priority": "不重要且不常用",
            "solution": "通过 cluster-key-rate-limit 插件 limit_by_per_ip，白名单 CIDR 设极大阈值实现",
            "risk": "中风险，需要使用 Go 版 cluster-key-rate-limit 插件（依赖 Redis）"
        },
        # 后端服务配置 (5个)
        "nginx.ingress.kubernetes.io/proxy-connect-timeout": {
            "category": "后端服务配置",
            "priority": "重要但不常用",
            "solution": "通过 EnvoyFilter cluster connect_timeout 或 DestinationRule connectTimeout 实现",
            "risk": "中风险，需要创建 EnvoyFilter 或 DestinationRule"
        },
        "nginx.ingress.kubernetes.io/proxy-read-timeout": {
            "category": "后端服务配置",
            "priority": "重要且常用",
            "solution": "全局：higress-config upstream.idleTimeout；路由级：EnvoyFilter route idle_timeout",
            "risk": "高风险，仅支持全局配置或需 EnvoyFilter 实现路由级配置"
        },
        "nginx.ingress.kubernetes.io/proxy-send-timeout": {
            "category": "后端服务配置",
            "priority": "不重要但常用",
            "solution": "全局：higress-config upstream.idleTimeout；Envoy 不区分读/写方向",
            "risk": "中风险，仅支持全局配置"
        },
        "nginx.ingress.kubernetes.io/proxy-cookie-domain": {
            "category": "后端服务配置",
            "priority": "不重要且不常用",
            "solution": "通过 WasmPlugin（transformer 插件）或 EnvoyFilter 修改响应头中 Set-Cookie 的 Domain 属性",
            "risk": "中风险，需要部署 transformer 插件或创建 EnvoyFilter"
        },
        "nginx.ingress.kubernetes.io/proxy-cookie-path": {
            "category": "后端服务配置",
            "priority": "不重要且不常用",
            "solution": "通过 WasmPlugin（transformer 插件）或 EnvoyFilter 修改响应头中 Set-Cookie 的 Path 属性",
            "risk": "中风险，需要部署 transformer 插件或创建 EnvoyFilter"
        },
        # 请求/响应头控制 (1个)
        "nginx.ingress.kubernetes.io/custom-headers": {
            "category": "请求/响应头控制",
            "priority": "重要且常用",
            "solution": "通过 higress.io/request-header-control-* 或 response-header-control-* 实现",
            "risk": "低风险，需要将 ConfigMap 引用改为内联注解声明"
        },
        # 安全防护 (2个)
        "nginx.ingress.kubernetes.io/enable-modsecurity": {
            "category": "安全防护",
            "priority": "重要且常用",
            "solution": "使用 Higress waf WASM 插件（基于 Coraza 引擎），配置 useCRS: true",
            "risk": "中风险，需要部署 WAF 插件"
        },
        "nginx.ingress.kubernetes.io/enable-owasp-core-rules": {
            "category": "安全防护",
            "priority": "重要且常用",
            "solution": "使用 Higress waf 插件，配置 useCRS: true 启用内嵌 OWASP CRS 规则集",
            "risk": "中风险，需要部署 WAF 插件"
        },
        # 可观测性 (1个)
        "nginx.ingress.kubernetes.io/enable-access-log": {
            "category": "可观测性",
            "priority": "不重要且不常用",
            "solution": "设为 false 时需通过 EnvoyFilter metadata_filter 按路由禁用日志；设为 true 或不设时无需处理",
            "risk": "中风险，配置复杂度显著高于 NGINX 单注解方式"
        },
        # 流量镜像 (1个)
        "nginx.ingress.kubernetes.io/mirror-target": {
            "category": "流量镜像",
            "priority": "重要但不常用",
            "solution": "使用 higress.io/mirror-target-service 或 mirror-target-fqdn，配合 mirror-percentage",
            "risk": "低风险，注解名称和参数格式不同但功能完全可达"
        },
        # IP 黑名单 (1个)
        "nginx.ingress.kubernetes.io/denylist-source-range": {
            "category": "访问控制",
            "priority": "重要且常用",
            "solution": "Higress 1.2.31+ 原生支持；低版本通过 ip-restriction WASM 插件 deny 模式实现",
            "risk": "低风险，需确认网关版本"
        },
    },

    # ❌ 不兼容 (35个)
    "❌ 不兼容": {
        # 重定向 (1个)
        "nginx.ingress.kubernetes.io/temporal-redirect-code": {
            "category": "重定向",
            "priority": "不重要且不常用",
            "solution": "redirect.go 中 temporal-redirect 硬编码为 302，未实现此注解的解析",
            "risk": "中风险，无法自定义临时重定向状态码（如 307）"
        },
        # 认证与授权 - External Auth (8个)
        "nginx.ingress.kubernetes.io/auth-signin": {
            "category": "认证与授权",
            "priority": "重要但不常用",
            "solution": "ext-auth WASM 插件不支持认证失败后重定向到登录页功能，无法实现",
            "risk": "高风险，Web 页面 SSO 场景需要登录页重定向"
        },
        "nginx.ingress.kubernetes.io/auth-snippet": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "Snippet 注解，Higress 不支持。大多数认证需求可通过 ext-auth 插件满足，自定义逻辑需 WASM 插件",
            "risk": "高风险，需要开发 WASM 插件实现自定义认证逻辑"
        },
        "nginx.ingress.kubernetes.io/auth-signin-redirect-param": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "ext-auth 插件不支持自定义重定向参数名",
            "risk": "低风险，仅影响 SSO 重定向场景"
        },
        "nginx.ingress.kubernetes.io/auth-request-redirect": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "ext-auth 插件不支持 X-Auth-Request-Redirect 头的自定义设置",
            "risk": "低风险，仅影响特定认证流程"
        },
        "nginx.ingress.kubernetes.io/auth-always-set-cookie": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "ext-auth 插件不支持此行为控制",
            "risk": "低风险，仅影响认证 Cookie 设置行为"
        },
        "nginx.ingress.kubernetes.io/auth-cache-duration": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "ext-auth 插件不支持认证缓存功能，每次请求均实时调用外部认证服务",
            "risk": "中风险，可能影响认证服务性能"
        },
        "nginx.ingress.kubernetes.io/auth-cache-key": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "ext-auth 插件不支持认证缓存功能，无法配置缓存 key",
            "risk": "中风险，依赖 auth-cache-duration"
        },
        # 认证与授权 - Keepalive (4个)
        "nginx.ingress.kubernetes.io/auth-keepalive": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "ext-auth 插件使用 Envoy HTTP 客户端，连接管理由 Envoy 集群配置控制，无法按 Ingress 粒度配置",
            "risk": "低风险，性能优化配置"
        },
        "nginx.ingress.kubernetes.io/auth-keepalive-requests": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "ext-auth 插件未暴露连接池配置",
            "risk": "低风险，性能优化配置"
        },
        "nginx.ingress.kubernetes.io/auth-keepalive-share-vars": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "NGINX Lua 子请求特有机制，Envoy 架构中不存在此概念",
            "risk": "低风险，可通过 ext-auth headers_to_add 部分替代"
        },
        "nginx.ingress.kubernetes.io/auth-keepalive-timeout": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "ext-auth 插件未暴露连接池超时配置",
            "risk": "低风险，性能优化配置"
        },
        # 认证与授权 - mTLS (1个)
        "nginx.ingress.kubernetes.io/auth-tls-error-page": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "Envoy 在 TLS 握手层面验证失败时直接返回 TLS 错误，无法进行 HTTP 层面重定向",
            "risk": "中风险，mTLS 失败时无法显示自定义错误页面"
        },
        # 认证与授权 - 多认证组合 (1个)
        "nginx.ingress.kubernetes.io/satisfy": {
            "category": "认证与授权",
            "priority": "不重要且不常用",
            "solution": "Envoy 各认证过滤器独立执行且均为必须通过语义，没有 any 模式",
            "risk": "中风险，多认证组合 any 逻辑需自定义 WASM 插件"
        },
        # SSL/TLS (1个)
        "nginx.ingress.kubernetes.io/ssl-passthrough": {
            "category": "SSL/TLS",
            "priority": "重要但不常用",
            "solution": "Higress 源码中未实现此注解的解析，Ingress 注解层面不支持 TLS 透传",
            "risk": "高风险，TLS 透传场景无法使用 Ingress 注解实现"
        },
        # 负载均衡 - Session Cookie 高级属性 (4个)
        "nginx.ingress.kubernetes.io/session-cookie-domain": {
            "category": "负载均衡",
            "priority": "不重要但常用",
            "solution": "Istio API v1.27 HTTPCookie 仅有 Name/Path/Ttl 字段，不包含 Domain",
            "risk": "中风险，跨子域名共享会话场景受影响"
        },
        "nginx.ingress.kubernetes.io/session-cookie-samesite": {
            "category": "负载均衡",
            "priority": "重要且常用",
            "solution": "Istio 1.28 已新增 SameSite 支持，待 Higress 升级 Istio API 后可原生支持",
            "risk": "高风险，CSRF 防护必需配置"
        },
        "nginx.ingress.kubernetes.io/session-cookie-secure": {
            "category": "负载均衡",
            "priority": "重要且常用",
            "solution": "Istio 1.28 已新增 Secure 支持，待 Higress 升级 Istio API 后可原生支持",
            "risk": "高风险，HTTPS 安全必需配置"
        },
        "nginx.ingress.kubernetes.io/session-cookie-conditional-samesite-none": {
            "category": "负载均衡",
            "priority": "不重要且不常用",
            "solution": "前提是 session-cookie-samesite 不支持，此注解自然也无法实现",
            "risk": "低风险，浏览器兼容性场景"
        },
        # 负载均衡 - 一致性哈希 Subset (2个)
        "nginx.ingress.kubernetes.io/upstream-hash-by-subset": {
            "category": "负载均衡",
            "priority": "不重要且不常用",
            "solution": "Envoy 一致性哈希实现没有 subset 模式概念",
            "risk": "低风险，仅影响 subset 哈希场景"
        },
        "nginx.ingress.kubernetes.io/upstream-hash-by-subset-size": {
            "category": "负载均衡",
            "priority": "不重要且不常用",
            "solution": "前提是 upstream-hash-by-subset 不支持",
            "risk": "低风险，依赖 upstream-hash-by-subset"
        },
        # 后端服务配置 (2个)
        "nginx.ingress.kubernetes.io/client-body-buffer-size": {
            "category": "后端服务配置",
            "priority": "不重要且不常用",
            "solution": "Envoy 不会将请求体写入磁盘，仅有连接级全局配置 per_connection_buffer_limit_bytes",
            "risk": "中风险，仅支持全局配置，语义不对等"
        },
        "nginx.ingress.kubernetes.io/proxy-buffers-number": {
            "category": "后端服务配置",
            "priority": "不重要且不常用",
            "solution": "Higress 全局配置 upstream.connectionBufferLimits 可控制，但语义不同（总大小 vs 缓冲区数量）",
            "risk": "低风险，缓冲机制不同但影响较小"
        },
        # 安全防护 (2个)
        "nginx.ingress.kubernetes.io/modsecurity-snippet": {
            "category": "安全防护",
            "priority": "不重要且不常用",
            "solution": "Higress waf 插件支持 secRules 传入自定义 SecRule 规则，可部分替代",
            "risk": "高风险，不支持任意 ModSecurity 指令"
        },
        "nginx.ingress.kubernetes.io/modsecurity-transaction-id": {
            "category": "安全防护",
            "priority": "不重要且不常用",
            "solution": "Coraza 无 ModSecurity 事务模型，如需请求追踪可结合 OpenTelemetry",
            "risk": "中风险，需要使用 WAF 插件"
        },
        # 可观测性 (3个)
        "nginx.ingress.kubernetes.io/enable-opentelemetry": {
            "category": "可观测性",
            "priority": "重要但不常用",
            "solution": "Envoy tracing provider 配置在 HCM 级别，无法按路由粒度开关",
            "risk": "中风险，per-Ingress 粒度的 tracing 开关语义不可达"
        },
        "nginx.ingress.kubernetes.io/opentelemetry-trust-incoming-span": {
            "category": "可观测性",
            "priority": "不重要且不常用",
            "solution": "Envoy 默认信任并传播 W3C Trace Context，行为不可按路由粒度调整",
            "risk": "低风险，默认行为通常满足需求"
        },
        "nginx.ingress.kubernetes.io/enable-rewrite-log": {
            "category": "可观测性",
            "priority": "不重要且不常用",
            "solution": "Envoy 完全没有对应的 rewrite 调试日志机制",
            "risk": "低风险，调试功能，可通过 accesslog 间接验证"
        },
        # Snippet 配置 (3个)
        "nginx.ingress.kubernetes.io/configuration-snippet": {
            "category": "Snippet配置",
            "priority": "重要且常用",
            "solution": "安全风险，Higress 不支持 snippet。需逐个分析 snippet 内容，通过 WASM 插件或内置插件组合替代",
            "risk": "高风险，必须重构自定义配置逻辑，使用频率高"
        },
        "nginx.ingress.kubernetes.io/server-snippet": {
            "category": "Snippet配置",
            "priority": "重要但不常用",
            "solution": "安全风险，Higress 不支持 snippet。需 WASM 插件替代",
            "risk": "高风险，必须重构自定义配置逻辑"
        },
        "nginx.ingress.kubernetes.io/stream-snippet": {
            "category": "Snippet配置",
            "priority": "不重要且不常用",
            "solution": "TCP/UDP snippet，Higress 不支持",
            "risk": "高风险，TCP/UDP 流量处理需要重新设计"
        },
        # 流量镜像 (1个)
        "nginx.ingress.kubernetes.io/mirror-host": {
            "category": "流量镜像",
            "priority": "不重要但常用",
            "solution": "Envoy route mirror 配置没有独立设置镜像请求 Host 的字段",
            "risk": "中风险，需通过 EnvoyFilter 或 WASM 插件实现"
        },
        # 限流与限速 (3个)
        "nginx.ingress.kubernetes.io/limit-burst-multiplier": {
            "category": "限流与限速",
            "priority": "不重要且不常用",
            "solution": "Higress 限流插件不支持配置突发倍数，迁移时直接忽略",
            "risk": "低风险，令牌桶算法天然允许瞬时突发到桶容量"
        },
        "nginx.ingress.kubernetes.io/limit-rate-after": {
            "category": "限流与限速",
            "priority": "不重要且不常用",
            "solution": "Envoy 流式架构没有 NGINX 的缓存响应+限速发送模型",
            "risk": "低风险，Envoy 天然流式转发"
        },
        "nginx.ingress.kubernetes.io/limit-rate": {
            "category": "限流与限速",
            "priority": "不重要且不常用",
            "solution": "Envoy 天然流式转发架构，没有按连接的响应速率限制功能",
            "risk": "低风险，Envoy 天然流式转发"
        },
    },

    # ⚠️ 部分兼容 (7个)
    "⚠️ 部分兼容": {
        "nginx.ingress.kubernetes.io/server-alias": {
            "category": "重定向",
            "priority": "不重要但常用",
            "solution": "Higress 1.2.30+ 支持精确域名和泛域名别名，不支持正则表达式域名别名",
            "risk": "中风险，正则域名别名不可用"
        },
        "nginx.ingress.kubernetes.io/backend-protocol": {
            "category": "后端服务配置",
            "priority": "重要且常用",
            "solution": "支持 HTTP/HTTP2/HTTPS/GRPC/GRPCS，不支持 AJP 和 FCGI 协议",
            "risk": "中风险，Tomcat AJP 和 PHP-FPM FastCGI 场景无法使用"
        },
        "nginx.ingress.kubernetes.io/proxy-http-version": {
            "category": "后端服务配置",
            "priority": "重要但不常用",
            "solution": "Envoy 向后端只支持 HTTP/1.1 和 HTTP/2，不支持 HTTP/1.0",
            "risk": "低风险，实际需要 HTTP/1.0 的后端极为罕见"
        },
        "nginx.ingress.kubernetes.io/load-balance": {
            "category": "负载均衡",
            "priority": "重要且常用",
            "solution": "支持 ROUND_ROBIN/LEAST_REQUEST/RANDOM/一致性哈希，不支持 ewma 算法",
            "risk": "中风险，使用 ewma 的场景需改用其他算法"
        },
        "nginx.ingress.kubernetes.io/upstream-hash-by": {
            "category": "负载均衡",
            "priority": "重要且常用",
            "solution": "仅支持单个变量（$http_*/$arg_*/$request_uri/$host/$remote_addr），不支持多变量组合",
            "risk": "中风险，多变量组合 hash key 场景无法实现"
        },
        "nginx.ingress.kubernetes.io/affinity-mode": {
            "category": "负载均衡",
            "priority": "重要但不常用",
            "solution": "仅支持 balanced 模式（默认行为），persistent 模式不支持",
            "risk": "中风险，需要强粘性会话的场景受影响"
        },
        "nginx.ingress.kubernetes.io/auth-tls-secret": {
            "category": "认证与授权",
            "priority": "重要但不常用",
            "solution": "对应 higress.io/auth-tls-secret，但 CA Secret 名称必须与 TLS 证书 Secret 同名或加 -cacert 后缀",
            "risk": "中风险，Secret 命名格式比 NGINX Ingress 更严格"
        },
    },

    # 🔴 无需迁移 (11个)
    "🔴 无需迁移": {
        "nginx.ingress.kubernetes.io/proxy-body-size": {
            "category": "后端服务配置",
            "priority": "重要且常用",
            "solution": "迁移时可安全忽略。NGINX 需要此限制是因为「先收完请求体再转发」架构会导致内存/磁盘爆炸；Envoy 流式转发架构下单连接内存上界仅为 per_connection_buffer_limit_bytes（默认 32KB），不会因请求体过大打爆网关。极少数需在网关层拦截超大请求的场景可通过 WasmPlugin 实现",
            "risk": "无风险，直接忽略"
        },
        "nginx.ingress.kubernetes.io/http2-push-preload": {
            "category": "其他特性",
            "priority": "不重要且不常用",
            "solution": "HTTP/2 Server Push 已被主流浏览器废弃（Chrome 106+ 移除）",
            "risk": "无风险，直接忽略"
        },
        "nginx.ingress.kubernetes.io/connection-proxy-header": {
            "category": "请求/响应头控制",
            "priority": "不重要且不常用",
            "solution": "Envoy 按 RFC 7230 自动处理 hop-by-hop 头，连接池默认 keep-alive",
            "risk": "无风险，直接忽略"
        },
        "nginx.ingress.kubernetes.io/ssl-prefer-server-ciphers": {
            "category": "SSL/TLS",
            "priority": "不重要且不常用",
            "solution": "Envoy 底层 BoringSSL 默认行为即为服务端优先选择加密套件顺序",
            "risk": "无风险，直接忽略"
        },
        "nginx.ingress.kubernetes.io/proxy-buffering": {
            "category": "后端服务配置",
            "priority": "不重要且不常用",
            "solution": "Envoy 天然流式处理，SSE/长轮询场景自动就是流式的",
            "risk": "无风险，直接忽略"
        },
        "nginx.ingress.kubernetes.io/proxy-buffer-size": {
            "category": "后端服务配置",
            "priority": "不重要且不常用",
            "solution": "Envoy 响应头处理机制不同，默认配置已够用",
            "risk": "无风险，直接忽略"
        },
        "nginx.ingress.kubernetes.io/proxy-busy-buffers-size": {
            "category": "后端服务配置",
            "priority": "不重要且不常用",
            "solution": "Envoy 流式架构天然不需要繁忙缓冲区概念",
            "risk": "无风险，直接忽略"
        },
        "nginx.ingress.kubernetes.io/proxy-max-temp-file-size": {
            "category": "后端服务配置",
            "priority": "不重要且不常用",
            "solution": "Envoy 不使用磁盘缓冲，不存在临时文件问题",
            "risk": "无风险，直接忽略"
        },
        "nginx.ingress.kubernetes.io/proxy-request-buffering": {
            "category": "后端服务配置",
            "priority": "不重要且不常用",
            "solution": "Envoy 天然流式处理，默认行为已满足大文件上传等场景需求",
            "risk": "无风险，直接忽略"
        },
        "nginx.ingress.kubernetes.io/service-upstream": {
            "category": "后端服务配置",
            "priority": "不重要且不常用",
            "solution": "Higress 默认通过 EDS 路由到 Endpoints（Pod IP），跳过 kube-proxy 性能更优",
            "risk": "无风险，直接忽略"
        },
        "nginx.ingress.kubernetes.io/session-cookie-change-on-failure": {
            "category": "负载均衡",
            "priority": "不重要且不常用",
            "solution": "Envoy outlier detection 和健康检查机制天然覆盖此注解核心诉求",
            "risk": "无风险，直接忽略"
        },
        "nginx.ingress.kubernetes.io/mirror-request-body": {
            "category": "流量镜像",
            "priority": "不重要且不常用",
            "solution": "Envoy 流量镜像天然包含完整请求（含请求体），默认行为与 NGINX 一致",
            "risk": "无风险，直接忽略"
        },
    },
}


class MigrationAnalyzer:
    """NGINX Ingress 迁移分析器"""

    def __init__(self, kubeconfig: str = None):
        self.kubeconfig = kubeconfig
        try:
            cmd = ["kubectl", "version", "--client", "-o", "json"]
            if self.kubeconfig:
                cmd.extend(["--kubeconfig", self.kubeconfig])
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            print("错误: 未找到 kubectl 命令，请先安装并配置到 PATH 中")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            print(f"❌ 初始化 kubectl 失败: {e}")
            sys.exit(1)

    def _get_nginx_ingress_class_names(self) -> Tuple[set, str]:
        """查询集群 IngressClass 资源，返回 NGINX 相关的 class name 集合和默认 class name。

        通过 IngressClass 的 spec.controller 字段判断是否为 NGINX 控制器。
        常见的 NGINX controller 值：
          - k8s.io/ingress-nginx
          - nginx.org/ingress-controller

        返回:
            (nginx_class_names, default_nginx_class): NGINX class 名称集合, 默认 NGINX class 名称（无则为空字符串）
        """
        nginx_class_names = set()
        default_nginx_class = ""

        try:
            cmd = ["kubectl", "get", "ingressclass", "-o", "json"]
            if self.kubeconfig:
                cmd.extend(["--kubeconfig", self.kubeconfig])
            completed = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            data = json.loads(completed.stdout)
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            print(f"⚠️  获取 IngressClass 失败，将回退到注解匹配模式: {e}")
            return nginx_class_names, default_nginx_class

        for item in data.get("items", []):
            metadata = item.get("metadata") or {}
            spec = item.get("spec") or {}
            class_name = metadata.get("name", "")
            controller = spec.get("controller", "")

            # 匹配 NGINX 控制器
            if "nginx" in controller.lower():
                nginx_class_names.add(class_name)
                # 检查是否为默认 IngressClass
                annotations = metadata.get("annotations") or {}
                if annotations.get("ingressclass.kubernetes.io/is-default-class") == "true":
                    default_nginx_class = class_name

        if nginx_class_names:
            print(f"📋 发现 NGINX IngressClass: {', '.join(sorted(nginx_class_names))}")
            if default_nginx_class:
                print(f"   默认 NGINX IngressClass: {default_nginx_class}")
        else:
            print("⚠️  未发现 NGINX IngressClass，将回退到注解匹配模式")

        return nginx_class_names, default_nginx_class

    def get_all_ingresses(self) -> List[Tuple[str, object]]:
        """获取所有 NGINX Ingress 资源

        识别策略：
        1. 通过 IngressClass 资源的 spec.controller 字段识别 NGINX 控制器对应的 class name
        2. spec.ingressClassName 匹配已识别的 NGINX class name
        3. 未设置 ingressClassName 的 Ingress，如果默认 IngressClass 是 NGINX，也纳入
        4. kubernetes.io/ingress.class 注解匹配已识别的 NGINX class name

        注意：不使用 nginx.ingress.kubernetes.io/ 注解前缀做兜底判断，
        因为 Higress 兼容该前缀，已迁移的 Ingress 也会带这些注解。

        IngressClass 查询失败时，回退到 spec.ingressClassName 模糊匹配 nginx。
        """
        ingresses: List[Tuple[str, object]] = []

        # 先查询 IngressClass 资源
        nginx_class_names, default_nginx_class = self._get_nginx_ingress_class_names()

        try:
            cmd = ["kubectl", "get", "ingress", "-A", "-o", "json"]
            if self.kubeconfig:
                cmd.extend(["--kubeconfig", self.kubeconfig])
            completed = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            data = json.loads(completed.stdout)
        except FileNotFoundError:
            print("错误: 未找到 kubectl 命令，请先安装并配置到 PATH 中")
            sys.exit(1)
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.strip() if e.stderr else str(e)
            print(f"❌ 获取 Ingress 列表失败: {stderr}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"❌ 解析 kubectl 输出失败: {e}")
            sys.exit(1)

        for item in data.get("items", []):
            metadata = item.get("metadata") or {}
            spec = item.get("spec") or {}
            ns_name = metadata.get("namespace", "default")
            annotations = metadata.get("annotations") or {}

            is_nginx = False
            ingress_class_name = spec.get("ingressClassName")

            if nginx_class_names:
                # 优先通过 IngressClass 判断
                if ingress_class_name and ingress_class_name in nginx_class_names:
                    is_nginx = True
                elif not ingress_class_name and default_nginx_class:
                    # 未指定 ingressClassName，且默认 IngressClass 是 NGINX
                    is_nginx = True
                # 回退：检查旧版 annotation
                if not is_nginx:
                    anno_class = annotations.get("kubernetes.io/ingress.class", "")
                    if anno_class in nginx_class_names:
                        is_nginx = True
            else:
                # IngressClass 查询失败或无结果，仅通过 spec.ingressClassName 模糊匹配
                if ingress_class_name and "nginx" in ingress_class_name.lower():
                    is_nginx = True

            if is_nginx:
                ingresses.append((ns_name, item))

        return ingresses

    def analyze_annotations(self, annotations: Dict[str, str]) -> Dict:
        """分析单个 Ingress 的注解兼容性

        返回按 5 种兼容性分类 + 未知注解 的分析结果。
        """
        result = {
            "完全兼容": [],
            "可等价替换": [],
            "不兼容": [],
            "部分兼容": [],
            "无需迁移": [],
            "未知注解": []
        }

        if not annotations:
            return result

        nginx_annotations = {k: v for k, v in annotations.items()
                             if k.startswith('nginx.ingress.kubernetes.io/')}

        for anno, value in nginx_annotations.items():
            found = False
            for compat_level, anno_dict in ANNOTATION_COMPATIBILITY.items():
                if anno in anno_dict:
                    info = anno_dict[anno].copy()
                    info['annotation'] = anno
                    info['value'] = value

                    if compat_level == "✅ 完全兼容":
                        result["完全兼容"].append(info)
                    elif compat_level == "🔵 可等价替换":
                        result["可等价替换"].append(info)
                    elif compat_level == "❌ 不兼容":
                        result["不兼容"].append(info)
                    elif compat_level == "⚠️ 部分兼容":
                        result["部分兼容"].append(info)
                    elif compat_level == "🔴 无需迁移":
                        result["无需迁移"].append(info)

                    found = True
                    break

            if not found:
                result["未知注解"].append({
                    "annotation": anno,
                    "value": value,
                    "category": "未知",
                    "priority": "需要人工评估",
                    "solution": "未在兼容性数据库中找到此注解，需要人工评估",
                    "risk": "需要人工评估"
                })

        return result

    def calculate_migration_risk(self, analysis: Dict) -> Tuple[str, int]:
        """计算迁移风险等级

        风险分类规则：
        - 有不兼容/未知注解 → 高风险
        - 有部分兼容/可等价替换注解 → 中风险
        - 只有完全兼容/无需迁移 → 兼容
        """
        incompatible_count = len(analysis.get("不兼容", []))
        unknown_count = len(analysis.get("未知注解", []))
        partial_count = len(analysis.get("部分兼容", []))
        replaceable_count = len(analysis.get("可等价替换", []))

        total_issues = incompatible_count + unknown_count + partial_count + replaceable_count

        if incompatible_count > 0 or unknown_count > 0:
            return "🔴 高风险", total_issues
        elif partial_count > 0 or replaceable_count > 0:
            return "🟡 中风险", total_issues
        else:
            return "✅ 兼容", 0

        total_issues = incompatible_count + unknown_count + partial_count + replaceable_count

        if incompatible_count > 0 or unknown_count > 0:
            return "🔴 高风险", total_issues
        elif partial_count > 0 or replaceable_count > 0:
            return "🟡 中风险", total_issues
        else:
            return "✅ 兼容", 0

    # ------------------------------------------------------------------
    # Route priority analysis
    # ------------------------------------------------------------------

    def analyze_route_priority(self, ingresses: List[Tuple[str, object]]) -> List[Dict]:
        """分析路由优先级冲突。

        NGINX 优先级:  exact > regex > prefix (相同类型按创建时间排序)
        Higress 优先级: exact > prefix > regex (相同类型按路径长度倒序)

        当 use-regex=true 时，regex 路径在 NGINX 中优先于 prefix 路径，
        但迁移到 Higress 后 prefix 路径优先级更高，可能导致流量路由到不同后端。
        """
        NGINX_PREFIX = "nginx.ingress.kubernetes.io/"
        REGEX_CHARS = set("()[]{}*+?|\\^$.")

        # 提取所有路径信息
        all_paths = []
        for ns_name, ing in ingresses:
            metadata = ing.get("metadata") or {}
            ing_name = metadata.get("name", "")
            annotations = metadata.get("annotations") or {}
            spec = ing.get("spec") or {}

            use_regex = annotations.get(
                f"{NGINX_PREFIX}use-regex", ""
            ).lower() == "true"

            for rule in spec.get("rules") or []:
                host = rule.get("host", "*")
                http = rule.get("http") or {}
                for http_path in http.get("paths") or []:
                    path_str = http_path.get("path", "/")
                    path_type_str = http_path.get("pathType", "ImplementationSpecific")
                    backend = http_path.get("backend") or {}

                    # Extract service info
                    svc = backend.get("service") or {}
                    if svc:
                        svc_name = svc.get("name", "")
                        port = svc.get("port") or {}
                        svc_port = str(port.get("number", port.get("name", "")))
                    else:
                        svc_name = backend.get("serviceName", "")
                        svc_port = str(backend.get("servicePort", ""))

                    # Determine effective path type
                    if path_type_str == "Exact":
                        effective_type = "Exact"
                    elif path_type_str == "Prefix":
                        if use_regex and any(c in REGEX_CHARS for c in path_str):
                            effective_type = "Regex"
                        else:
                            effective_type = "Prefix"
                    else:  # ImplementationSpecific
                        effective_type = "Regex" if use_regex else "Prefix"

                    all_paths.append({
                        "ingress": f"{ns_name}/{ing_name}",
                        "host": host,
                        "path": path_str,
                        "path_type": effective_type,
                        "service": f"{svc_name}:{svc_port}",
                        "use_regex": use_regex,
                    })

        # Group by host and find conflicts
        paths_by_host = defaultdict(list)
        for p in all_paths:
            paths_by_host[p["host"]].append(p)

        conflicts = []
        for host, paths in paths_by_host.items():
            regex_paths = [p for p in paths if p["path_type"] == "Regex"]
            prefix_paths = [p for p in paths if p["path_type"] == "Prefix"]

            if not regex_paths or not prefix_paths:
                continue

            for rp in regex_paths:
                for pp in prefix_paths:
                    # Skip same ingress + same service
                    if rp["ingress"] == pp["ingress"] and rp["service"] == pp["service"]:
                        continue

                    # Check path overlap heuristic
                    if self._paths_may_overlap(rp["path"], pp["path"]):
                        conflicts.append({
                            "host": host,
                            "regex_ingress": rp["ingress"],
                            "regex_path": rp["path"],
                            "regex_backend": rp["service"],
                            "prefix_ingress": pp["ingress"],
                            "prefix_path": pp["path"],
                            "prefix_backend": pp["service"],
                            "description": (
                                f"host={host}: regex 路径 '{rp['path']}' "
                                f"(Ingress: {rp['ingress']}, 后端: {rp['service']}) "
                                f"在 NGINX 中优先于 prefix 路径 '{pp['path']}' "
                                f"(Ingress: {pp['ingress']}, 后端: {pp['service']}), "
                                f"但在 Higress 中 prefix 路径优先级更高, "
                                f"可能导致流量路由到不同后端"
                            ),
                        })

        return conflicts

    @staticmethod
    def _paths_may_overlap(regex_path: str, prefix_path: str) -> bool:
        """启发式检查 regex 路径和 prefix 路径是否可能重叠。"""
        regex_chars = set("()[]{}*+?|\\^$.")
        static_prefix = []
        for ch in regex_path:
            if ch in regex_chars:
                break
            static_prefix.append(ch)
        regex_static = "".join(static_prefix).rstrip("/") or "/"
        prefix_clean = prefix_path.rstrip("/") or "/"

        return (
            regex_static.startswith(prefix_clean)
            or prefix_clean.startswith(regex_static)
        )

    def _build_route_priority_html(self, conflicts: List[Dict]) -> str:
        """构建路由优先级警告 HTML。"""
        if not conflicts:
            return ""

        rows_html = []
        for i, c in enumerate(conflicts, 1):
            rows_html.append(f'''
                <tr>
                    <td>{i}</td>
                    <td><code>{c['host']}</code></td>
                    <td><code>{c['regex_path']}</code></td>
                    <td>{c['regex_ingress']}</td>
                    <td>{c['regex_backend']}</td>
                    <td><code>{c['prefix_path']}</code></td>
                    <td>{c['prefix_ingress']}</td>
                    <td>{c['prefix_backend']}</td>
                </tr>''')

        return f'''
        <div class="section" id="section-route-priority">
            <h2><span class="icon">🔀</span>路由优先级变更警告</h2>
            <div style="background: #fff7e6; border-left: 4px solid #faad14; padding: 15px; border-radius: 6px; margin-bottom: 20px;">
                <p style="font-weight: 500; color: #d48806; margin-bottom: 10px;">⚠️ NGINX 和 Higress 的路由优先级规则不同，可能导致迁移后流量路由到不同后端。</p>
                <ul style="color: #666; font-size: 14px; padding-left: 20px; margin: 0;">
                    <li>NGINX 优先级：<code>exact &gt; regex &gt; prefix</code>（相同类型按创建时间排序）</li>
                    <li>Higress 优先级：<code>exact &gt; prefix &gt; regex</code>（相同类型按路径长度倒序）</li>
                </ul>
                <p style="color: #666; font-size: 14px; margin-top: 10px;">以下 Ingress 使用了 <code>use-regex</code> 注解，且存在 regex 路径与 prefix 路径的优先级冲突：</p>
            </div>
            <div style="overflow-x: auto;">
                <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                    <thead>
                        <tr style="background: #fafbfc; border-bottom: 2px solid #e4e7ed;">
                            <th style="padding: 10px; text-align: left; white-space: nowrap;">序号</th>
                            <th style="padding: 10px; text-align: left;">Host</th>
                            <th style="padding: 10px; text-align: left;">Regex 路径 (NGINX 优先)</th>
                            <th style="padding: 10px; text-align: left;">Regex Ingress</th>
                            <th style="padding: 10px; text-align: left;">Regex 后端</th>
                            <th style="padding: 10px; text-align: left;">Prefix 路径 (Higress 优先)</th>
                            <th style="padding: 10px; text-align: left;">Prefix Ingress</th>
                            <th style="padding: 10px; text-align: left;">Prefix 后端</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows_html)}
                    </tbody>
                </table>
            </div>
            <div class="solution-box" style="margin-top: 15px;">
                <h4>💡 建议操作</h4>
                <p style="color: #d48806; font-size: 13px; margin-bottom: 10px;">⚠️ 此优先级差异没有完美的自动兼容方案，需要根据实际业务逐一评估：</p>
                <ol style="color: #666; font-size: 13px; padding-left: 20px; margin: 0;">
                    <li><b>确认实际影响</b>：分析真实流量是否会同时命中 regex 和 prefix 路径。如果实际请求 URL 不会同时匹配两者，则优先级变化不影响路由行为</li>
                    <li><b>将 prefix 路径也改为 regex</b>：给冲突的 prefix Ingress 加上 <code>use-regex: "true"</code>，使两者都变为 regex 类型，在 Higress 中按路径长度排序，避免优先级反转。<br/>
                        <span style="color: #d48806;">⚠️ 注意：</span>加上 <code>use-regex</code> 后，原来的 Prefix 路径（如 <code>/admin</code>）会被当作正则表达式匹配，语义发生变化（如 <code>/some/admin</code> 也会被匹配到）。需要同时将 path 改写为等效的正则表达式以保持原有前缀匹配行为，例如将 <code>/admin</code> 改为 <code>/admin(/|$)(.*)</code></li>
                    <li><b>缩小 prefix 路径范围</b>：将 prefix 路径改为更精确的路径（如 <code>/admin/dashboard</code> 代替 <code>/admin</code>），减少与 regex 路径的重叠</li>
                    <li><b>合并 Ingress</b>：将冲突的 regex 和 prefix 路径合并到同一个 Ingress 中，统一后端服务，消除优先级冲突</li>
                    <li><b>灰度验证</b>：迁移前在测试环境用真实流量回放验证路由行为，确保关键路径不受影响</li>
                </ol>
            </div>
        </div>'''

    def generate_html_report(self, ingresses, detailed_results, total_stats, risk_stats,
                             blocking_issues, all_annotations_by_type, ingress_classification,
                             can_migrate, output_file, route_priority_conflicts=None):
        """生成可交互的 HTML 报告"""
        generated_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        total_ingresses_count = len(ingresses)
        blocking_issues_count = len(blocking_issues)

        can_migrate_text = "✅ 可平滑迁移" if can_migrate else "⚠️ 需处理后迁移"
        can_migrate_class = "risk-low" if can_migrate else "risk-high"

        # 映射统计类别到问题分组 ID
        stat_to_section = {
            "完全兼容": "section-compatible",
            "可等价替换": "section-replaceable",
            "不兼容": "section-incompatible",
            "部分兼容": "section-partial",
            "无需迁移": "section-ignore",
            "未知注解": "section-unknown"
        }

        # 注解统计 HTML
        annotation_stats_html = []
        for key, count in total_stats.items():
            if count > 0:
                section_id = stat_to_section.get(key, "")
                click_handler = f'onclick="scrollToSection(\'{section_id}\')"' if section_id else ''
                cursor_style = 'style="cursor: pointer;"' if section_id else ''
                annotation_stats_html.append(f'''
                <div class="stat-item stat-clickable" {click_handler} {cursor_style}>
                    <div class="label">{key}</div>
                    <div class="count">{count}</div>
                </div>''')

        # 阻塞性问题 HTML（不兼容 + 未知注解）
        blocking_issues_html = []
        if blocking_issues:
            issues_by_type = defaultdict(list)
            for issue in blocking_issues:
                issues_by_type[issue['type']].append(issue)

            type_to_section = {
                "不兼容": "section-incompatible",
                "未知注解": "section-unknown"
            }

            for issue_type, issues in issues_by_type.items():
                issues_by_anno = defaultdict(list)
                for issue in issues:
                    issues_by_anno[issue['annotation']].append(issue['ingress'])

                section_id = type_to_section.get(issue_type, "")
                group_id = section_id.replace('section-', 'group-')

                blocking_issues_html.append(f'''
                <div class="issue-group" id="{section_id}">
                    <div class="issue-group-header" onclick="toggleIssueGroup('{group_id}')">
                        <span class="group-title">{issue_type} ({len(issues)} 个)</span>
                        <span class="group-icon collapsed" id="icon-{group_id}">▼</span>
                    </div>
                    <div class="issue-group-content" id="content-{group_id}">''')

                for anno, ingresses_list in issues_by_anno.items():
                    issue_id = anno.replace('/', '_').replace('.', '_')
                    sample_issue = next(i for i in issues if i['annotation'] == anno)
                    badge_class = "badge-danger" if issue_type == "不兼容" else "badge-warning"

                    ingress_tags = ''.join([f'<span class="ingress-tag">{ing}</span>' for ing in ingresses_list[:10]])
                    if len(ingresses_list) > 10:
                        ingress_tags += f'<span class="ingress-tag">... 还有 {len(ingresses_list) - 10} 个</span>'

                    solution_html = f'''
                    <div class="solution-box">
                        <h4>💡 解决方案</h4>
                        <p>{sample_issue.get('solution', '暂无')}</p>
                    </div>''' if sample_issue.get('solution') else ''

                    risk_html = f'''
                    <div class="info-row">
                        <div class="info-label">⚠️ 风险说明</div>
                        <div class="info-value">{sample_issue.get('risk', '未知')}</div>
                    </div>''' if sample_issue.get('risk') else ''

                    blocking_issues_html.append(f'''
                    <div class="issue-item">
                        <div class="issue-header" onclick="toggleIssue(this)">
                            <div class="checkbox-wrapper">
                                <input type="checkbox" data-issue-id="{issue_id}" data-annotation="{anno}"
                                       onclick="event.stopPropagation()">
                            </div>
                            <div class="issue-title">
                                <span class="badge {badge_class}">{issue_type}</span>
                                <span class="annotation-name">
                                    <span class="anno-text">{anno}</span>
                                    <span class="copy-btn" onclick="event.stopPropagation(); copyAnnotation(this, '{anno}')" title="复制注解名称">📋</span>
                                </span>
                                <span class="ingress-count">影响 {len(ingresses_list)} 个 Ingress</span>
                            </div>
                            <span class="expand-icon">▼</span>
                        </div>
                        <div class="issue-content">
                            <div class="info-row">
                                <div class="info-label">📦 分类</div>
                                <div class="info-value">{sample_issue.get('category', '未分类')}</div>
                            </div>
                            <div class="info-row">
                                <div class="info-label">⭐ 优先级</div>
                                <div class="info-value">{sample_issue.get('priority', '未知')}</div>
                            </div>
                            {risk_html}
                            <div class="info-row">
                                <div class="info-label">🎯 影响范围</div>
                                <div class="info-value">
                                    <div class="ingress-list">{ingress_tags}</div>
                                </div>
                            </div>
                            {solution_html}
                            <div class="action-box">
                                <h4>📝 处理方式说明</h4>
                                <textarea class="action-input" data-issue-id="{issue_id}"
                                          placeholder="请输入具体的处理方式、负责人、预计完成时间等..."
                                          rows="3"></textarea>
                            </div>
                        </div>
                    </div>''')

                blocking_issues_html.append('</div></div>')
        else:
            blocking_issues_html.append('<p style="color: #67c23a;">✅ 未发现阻塞性问题</p>')

        # Ingress 分类 HTML
        ingress_classification_html = self._build_ingress_classification_html(ingress_classification)

        # 其他注解列表 HTML（排除已在阻塞性问题中显示的不兼容和未知注解）
        all_annotations_html = self._build_annotations_list_html(all_annotations_by_type)

        # 建议列表
        recommendations_html = self._build_recommendations_html(can_migrate)

        recommendations_title = "✅ 可以平滑迁移" if can_migrate else "⚠️ 需处理后迁移"

        # 路由优先级警告 HTML
        route_priority_html = self._build_route_priority_html(route_priority_conflicts or [])

        # 组装完整 HTML
        html_content = self._assemble_html(
            generated_time, total_ingresses_count, blocking_issues_count,
            can_migrate_class, recommendations_title,
            ''.join(annotation_stats_html), ''.join(blocking_issues_html),
            ''.join(ingress_classification_html), ''.join(all_annotations_html),
            recommendations_html, route_priority_html
        )

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"✅ HTML 报告已保存到: {output_file}")
        except Exception as e:
            print(f"❌ 保存 HTML 报告失败: {e}")

    def _build_ingress_classification_html(self, ingress_classification):
        """构建 Ingress 分类视角 HTML"""
        html_parts = []
        classification_config = {
            "需改造-高风险": {"icon": "🔴", "color": "#f56c6c", "bg": "#fef0f0",
                          "description": "有不兼容或未知注解，需重点处理"},
            "需改造-中风险": {"icon": "🟡", "color": "#e6a23c", "bg": "#fdf6ec",
                          "description": "有部分兼容或可等价替换的注解，需要改造"},
            "完美兼容": {"icon": "✅", "color": "#67c23a", "bg": "#f0f9ff",
                       "description": "所有注解都完全兼容或无需迁移，可直接迁移"}
        }

        for category in ["需改造-高风险", "需改造-中风险", "完美兼容"]:
            ingresses_in_category = ingress_classification.get(category, [])
            if not ingresses_in_category:
                continue

            config = classification_config[category]
            html_parts.append(f'''
            <div class="ingress-category" style="margin-bottom: 25px;">
                <div style="background: {config['bg']}; padding: 15px; border-left: 4px solid {config['color']}; border-radius: 6px; margin-bottom: 15px;">
                    <h4 style="margin: 0; color: {config['color']}; font-size: 16px;">
                        {config['icon']} {category} ({len(ingresses_in_category)} 个)
                    </h4>
                    <p style="margin: 5px 0 0 0; font-size: 13px; color: #666;">{config['description']}</p>
                </div>
                <div class="ingress-items">''')

            for ing_info in ingresses_in_category:
                ing_id = ing_info['identifier'].replace('/', '_').replace('-', '_')
                risk_level = ing_info['risk_level']
                if "🔴" in risk_level:
                    badge_class, badge_text = "badge-danger", "高风险"
                elif "🟡" in risk_level:
                    badge_class, badge_text = "badge-warning", "中风险"
                else:
                    badge_class, badge_text = "badge-success", "兼容"

                anno_summary = [f"{t}: {c}" for t, c in ing_info['annotation_counts'].items() if c > 0]
                anno_summary_text = " | ".join(anno_summary) if anno_summary else "无注解"

                blocking_html = ""
                if ing_info['blocking_annotations']:
                    blocking_items = []
                    for ba in ing_info['blocking_annotations']:
                        blocking_items.append(f'''
                        <div style="margin: 5px 0; padding: 8px; background: #fafbfc; border-left: 3px solid #f56c6c; border-radius: 3px;">
                            <div style="font-weight: 500; color: #f56c6c;">
                                <span class="badge badge-danger" style="margin-right: 5px;">{ba['type']}</span>
                                <code style="font-size: 12px;">{ba['annotation']}</code>
                            </div>
                            <div style="font-size: 12px; color: #666; margin-top: 5px;">解决方案: {ba['solution']}</div>
                        </div>''')
                    blocking_html = f'''
                    <div style="margin-top: 10px;">
                        <div style="font-size: 13px; font-weight: 500; color: #666; margin-bottom: 5px;">需处理的注解:</div>
                        {''.join(blocking_items)}
                    </div>'''

                attention_html = ""
                if ing_info.get('attention_annotations'):
                    type_badge_map = {
                        '可等价替换': ('badge-info', '#409eff'),
                        '部分兼容': ('badge-warning', '#e6a23c'),
                    }
                    attention_items = []
                    for aa in ing_info['attention_annotations']:
                        badge_cls, border_color = type_badge_map.get(aa['type'], ('badge-info', '#409eff'))
                        attention_items.append(f'''
                        <div style="margin: 5px 0; padding: 8px; background: #fafbfc; border-left: 3px solid {border_color}; border-radius: 3px;">
                            <div style="font-weight: 500; color: {border_color};">
                                <span class="badge {badge_cls}" style="margin-right: 5px;">{aa['type']}</span>
                                <code style="font-size: 12px;">{aa['annotation']}</code>
                            </div>
                            <div style="font-size: 12px; color: #666; margin-top: 5px;">解决方案: {aa['solution']}</div>
                        </div>''')
                    attention_html = f'''
                    <div style="margin-top: 10px;">
                        <div style="font-size: 13px; font-weight: 500; color: #666; margin-bottom: 5px;">需关注的注解（可等价替换/部分兼容）:</div>
                        {''.join(attention_items)}
                    </div>'''

                html_parts.append(f'''
                <div class="issue-item">
                    <div class="issue-header" onclick="toggleIngress('{ing_id}')">
                        <div class="checkbox-wrapper">
                            <input type="checkbox" data-ingress-id="{ing_id}" onclick="event.stopPropagation()">
                        </div>
                        <div class="issue-title">
                            <span class="badge {badge_class}">{badge_text}</span>
                            <span class="annotation-name">
                                <span class="anno-text">{ing_info['identifier']}</span>
                                <span class="copy-btn" onclick="event.stopPropagation(); copyAnnotation(this, '{ing_info['identifier']}')" title="复制">📋</span>
                            </span>
                            <span class="ingress-count">{anno_summary_text}</span>
                        </div>
                        <span class="expand-icon" id="icon-{ing_id}">▼</span>
                    </div>
                    <div class="issue-content" id="content-{ing_id}">
                        <div class="info-row"><div class="info-label">📦 命名空间</div><div class="info-value">{ing_info['namespace']}</div></div>
                        <div class="info-row"><div class="info-label">📝 名称</div><div class="info-value">{ing_info['name']}</div></div>
                        <div class="info-row"><div class="info-label">⚠️ 风险等级</div><div class="info-value">{ing_info['risk_level']}</div></div>
                        {blocking_html}
                        {attention_html}
                        <div class="action-box">
                            <h4>📝 处理方式说明</h4>
                            <textarea class="action-input" data-ingress-id="{ing_id}"
                                      placeholder="请输入具体的处理方式、负责人、预计完成时间等..." rows="3"></textarea>
                        </div>
                    </div>
                </div>''')

            html_parts.append('</div></div>')

        return html_parts

    def _build_annotations_list_html(self, all_annotations_by_type):
        """构建其他注解列表 HTML（排除已在阻塞性问题中显示的不兼容和未知注解）"""
        html_parts = []
        category_config = {
            "部分兼容": {"badge": "badge-warning", "section_id": "section-partial"},
            "可等价替换": {"badge": "badge-info", "section_id": "section-replaceable"},
            "完全兼容": {"badge": "badge-success", "section_id": "section-compatible"},
            "无需迁移": {"badge": "badge-info", "section_id": "section-ignore"},
        }

        for anno_type in ["部分兼容", "可等价替换", "完全兼容", "无需迁移"]:
            annotations = all_annotations_by_type.get(anno_type, [])
            if not annotations:
                continue

            config = category_config.get(anno_type, {"badge": "badge-info", "section_id": ""})
            section_id = config["section_id"]
            badge_class = config["badge"]
            group_id = section_id.replace('section-', 'group-')

            html_parts.append(f'''
            <div class="issue-group" id="{section_id}">
                <div class="issue-group-header" onclick="toggleIssueGroup('{group_id}')">
                    <span class="group-title">{anno_type} ({len(annotations)} 个)</span>
                    <span class="group-icon collapsed" id="icon-{group_id}">▼</span>
                </div>
                <div class="issue-group-content" id="content-{group_id}">''')

            for anno_info in annotations:
                anno = anno_info['annotation']
                ingresses_list = anno_info.get('ingresses', [])
                issue_id = anno.replace('/', '_').replace('.', '_')

                ingress_tags = ''.join([f'<span class="ingress-tag">{ing}</span>' for ing in ingresses_list[:10]])
                if len(ingresses_list) > 10:
                    ingress_tags += f'<span class="ingress-tag">... 还有 {len(ingresses_list) - 10} 个</span>'

                solution_html = f'''
                <div class="solution-box">
                    <h4>💡 解决方案</h4>
                    <p>{anno_info.get('solution', '暂无')}</p>
                </div>''' if anno_info.get('solution') else ''

                risk_html = f'''
                <div class="info-row">
                    <div class="info-label">⚠️ 风险说明</div>
                    <div class="info-value">{anno_info.get('risk', '无风险')}</div>
                </div>''' if anno_info.get('risk') else ''

                html_parts.append(f'''
                <div class="issue-item">
                    <div class="issue-header" onclick="toggleIssue(this)">
                        <div class="checkbox-wrapper">
                            <input type="checkbox" data-issue-id="{issue_id}_all" data-annotation="{anno}"
                                   onclick="event.stopPropagation()">
                        </div>
                        <div class="issue-title">
                            <span class="badge {badge_class}">{anno_type}</span>
                            <span class="annotation-name">
                                <span class="anno-text">{anno}</span>
                                <span class="copy-btn" onclick="event.stopPropagation(); copyAnnotation(this, '{anno}')" title="复制注解名称">📋</span>
                            </span>
                            <span class="ingress-count">影响 {len(ingresses_list)} 个 Ingress</span>
                        </div>
                        <span class="expand-icon">▼</span>
                    </div>
                    <div class="issue-content">
                        <div class="info-row"><div class="info-label">📦 分类</div><div class="info-value">{anno_info.get('category', '未分类')}</div></div>
                        <div class="info-row"><div class="info-label">⭐ 优先级</div><div class="info-value">{anno_info.get('priority', '未知')}</div></div>
                        {risk_html}
                        <div class="info-row">
                            <div class="info-label">🎯 影响范围</div>
                            <div class="info-value"><div class="ingress-list">{ingress_tags}</div></div>
                        </div>
                        {solution_html}
                        <div class="action-box">
                            <h4>📝 处理方式说明</h4>
                            <textarea class="action-input" data-issue-id="{issue_id}_all"
                                      placeholder="请输入具体的处理方式、负责人、预计完成时间等..." rows="3"></textarea>
                        </div>
                    </div>
                </div>''')

            html_parts.append('</div></div>')

        return html_parts

    def _build_recommendations_html(self, can_migrate):
        """构建迁移建议 HTML"""
        if can_migrate:
            items = [
                "处理所有「可等价替换」的注解，部署必要的 WASM 插件",
                "评估「部分兼容」注解的实际使用值是否在兼容范围内",
                "在测试环境进行完整功能测试",
                "配置监控和告警，准备回滚方案",
                "灰度发布到生产环境"
            ]
            return '\n'.join([f'<li>{item}</li>' for item in items])

        recommendations_by_priority = {
            "P0": [
                "处理所有 snippet 类注解（configuration-snippet/server-snippet/stream-snippet），开发对应的 WASM 插件或使用内置插件组合替代",
                "迁移 auth-type/auth-secret 到 basic-auth WASM 插件（Higress v2.0.0+ 推荐）",
                "评估 auth-url 等外部认证注解，配置 ext-auth WASM 插件的 forward_auth 模式",
                "调整超时配置：proxy-connect-timeout → EnvoyFilter cluster connect_timeout；proxy-read/send-timeout → higress-config upstream.idleTimeout 或 EnvoyFilter route idle_timeout"
            ],
            "P1": [
                "部署限流插件（key-rate-limit / cluster-key-rate-limit）替代 limit-rps/limit-rpm",
                "部署 WAF 插件替代 enable-modsecurity/enable-owasp-core-rules",
                "统一头部控制到 higress.io/request-header-control-* / response-header-control-*",
                "迁移流量镜像到 higress.io/mirror-target-service 或 mirror-target-fqdn",
                "评估部分兼容注解（load-balance/upstream-hash-by/backend-protocol 等）的实际使用值"
            ],
            "P2": [
                "关注 Higress 升级 Istio API 至 1.28+ 后 session-cookie-samesite/secure 的原生支持",
                "配置可观测性（tracing/logging），enable-access-log: false 需通过 EnvoyFilter metadata_filter 实现",
                "在测试环境充分验证后，再考虑生产环境迁移"
            ]
        }

        html_parts = []
        for priority in ["P0", "P1", "P2"]:
            items = recommendations_by_priority.get(priority, [])
            if not items:
                continue
            priority_class = f"priority-{priority.lower()}"
            items_html = '\n'.join([f'<li>{item}</li>' for item in items])
            html_parts.append(f'''
            <div class="priority-group">
                <div class="priority-header {priority_class}" onclick="togglePriority('{priority.lower()}')">
                    <span class="priority-badge">{priority}</span>
                    <span class="priority-count">({len(items)} 项)</span>
                    <span class="priority-toggle-icon" id="toggle-{priority.lower()}">▼</span>
                </div>
                <ul class="priority-content expanded" id="content-{priority.lower()}">
                    {items_html}
                </ul>
            </div>''')

        return '\n'.join(html_parts)

    def _assemble_html(self, generated_time, total_ingresses_count, blocking_issues_count,
                       can_migrate_class, recommendations_title,
                       annotation_stats_html, blocking_issues_html,
                       ingress_classification_html, all_annotations_html,
                       recommendations_html, route_priority_html=""):
        """组装完整 HTML 报告"""
        return """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NGINX Ingress to Higress 迁移分析报告</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', 'Helvetica Neue', Helvetica, Arial, sans-serif; background: #f5f7fa; color: #333; line-height: 1.6; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .header .meta { opacity: 0.9; font-size: 14px; }
        .section { padding: 30px; border-top: 1px solid #eee; }
        .section h2 { font-size: 20px; margin-bottom: 20px; color: #333; display: flex; align-items: center; }
        .section h2 .icon { margin-right: 10px; font-size: 24px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-item { background: #f8f9fa; padding: 15px; border-radius: 6px; border-left: 3px solid #667eea; transition: all 0.3s; }
        .stat-item.stat-clickable { cursor: pointer; }
        .stat-item.stat-clickable:hover { background: #e8f0fe; transform: translateY(-2px); box-shadow: 0 4px 12px rgba(102,126,234,0.2); }
        .stat-item .label { font-size: 13px; color: #666; margin-bottom: 5px; }
        .stat-item .count { font-size: 24px; font-weight: bold; color: #333; }
        .issue-group { margin-bottom: 30px; }
        .issue-group-header { font-size: 16px; color: #666; margin-bottom: 15px; padding: 12px 15px; border-left: 3px solid #e6a23c; background: #fafbfc; cursor: pointer; display: flex; justify-content: space-between; align-items: center; transition: all 0.3s; user-select: none; }
        .issue-group-header:hover { background: #f0f2f5; }
        .issue-group-header .group-title { font-weight: 600; }
        .issue-group-header .group-icon { font-size: 12px; transition: transform 0.3s; }
        .issue-group-header .group-icon.collapsed { transform: rotate(-90deg); }
        .issue-group-content { max-height: 0; overflow: hidden; transition: max-height 0.3s ease-out; }
        .issue-group-content.expanded { max-height: 100000px; transition: max-height 0.5s ease-in; }
        .issue-item { background: #fff; border: 1px solid #e4e7ed; border-radius: 6px; margin-bottom: 15px; overflow: hidden; transition: box-shadow 0.3s; }
        .issue-item:hover { box-shadow: 0 2px 12px rgba(0,0,0,0.1); }
        .issue-header { display: flex; align-items: center; padding: 15px; background: #fafbfc; cursor: pointer; user-select: none; }
        .issue-header:hover { background: #f5f7fa; }
        .checkbox-wrapper { margin-right: 15px; }
        .checkbox-wrapper input[type="checkbox"] { width: 18px; height: 18px; cursor: pointer; }
        .issue-title { flex: 1; display: flex; align-items: center; gap: 10px; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: 500; }
        .badge-danger { background: #fef0f0; color: #f56c6c; }
        .badge-warning { background: #fdf6ec; color: #e6a23c; }
        .badge-info { background: #f4f4f5; color: #909399; }
        .badge-success { background: #f0f9ff; color: #409eff; }
        .annotation-name { font-family: 'Monaco','Menlo','Courier New',monospace; font-size: 13px; color: #333; font-weight: 500; display: inline-flex; align-items: center; gap: 8px; }
        .copy-btn { cursor: pointer; color: #909399; font-size: 14px; padding: 2px 6px; border-radius: 3px; transition: all 0.3s; opacity: 0; }
        .annotation-name:hover .copy-btn { opacity: 1; }
        .copy-btn:hover { color: #409eff; background: #ecf5ff; }
        .ingress-count { color: #909399; font-size: 13px; }
        .expand-icon { margin-left: auto; transition: transform 0.3s; color: #909399; }
        .expand-icon.expanded { transform: rotate(180deg); }
        .issue-content { display: none; padding: 15px; border-top: 1px solid #e4e7ed; }
        .issue-content.expanded { display: block; }
        .info-row { display: grid; grid-template-columns: 120px 1fr; padding: 8px 0; border-bottom: 1px solid #f5f7fa; }
        .info-row:last-child { border-bottom: none; }
        .info-label { font-weight: 500; color: #666; }
        .info-value { color: #333; }
        .ingress-list { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 5px; }
        .ingress-tag { background: #ecf5ff; color: #409eff; padding: 2px 8px; border-radius: 3px; font-size: 12px; font-family: 'Monaco','Menlo','Courier New',monospace; }
        .solution-box { background: #f0f9ff; border-left: 3px solid #409eff; padding: 12px; margin-top: 10px; border-radius: 4px; }
        .solution-box h4 { color: #409eff; font-size: 14px; margin-bottom: 8px; }
        .solution-box p { color: #666; font-size: 13px; line-height: 1.6; }
        .action-box { background: #fff7e6; border-left: 3px solid #faad14; padding: 12px; margin-top: 10px; border-radius: 4px; }
        .action-box h4 { color: #faad14; font-size: 14px; margin-bottom: 8px; }
        .action-input { width: 100%; padding: 8px; border: 1px solid #d9d9d9; border-radius: 4px; font-size: 13px; margin-top: 5px; font-family: inherit; }
        .action-input:focus { outline: none; border-color: #409eff; box-shadow: 0 0 0 2px rgba(64,158,255,0.1); }
        .tab-buttons { display: flex; gap: 10px; border-bottom: 2px solid #e4e7ed; margin-bottom: 20px; }
        .tab-button { padding: 12px 24px; background: none; border: none; border-bottom: 3px solid transparent; cursor: pointer; font-size: 15px; font-weight: 500; color: #606266; transition: all 0.3s; position: relative; bottom: -2px; }
        .tab-button:hover { color: #409eff; }
        .tab-button.active { color: #409eff; border-bottom-color: #409eff; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .toolbar { position: sticky; top: 0; background: white; padding: 15px 30px; border-bottom: 2px solid #e4e7ed; display: flex; gap: 10px; align-items: center; z-index: 100; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 13px; font-weight: 500; transition: all 0.3s; }
        .btn-primary { background: #409eff; color: white; }
        .btn-primary:hover { background: #66b1ff; }
        .btn-success { background: #67c23a; color: white; }
        .btn-success:hover { background: #85ce61; }
        .btn-secondary { background: #f4f4f5; color: #606266; }
        .btn-secondary:hover { background: #e4e7ed; }
        .filter-group { display: flex; gap: 10px; margin-left: auto; }
        .filter-btn { padding: 6px 12px; border: 1px solid #dcdfe6; background: white; border-radius: 4px; cursor: pointer; font-size: 12px; transition: all 0.3s; }
        .filter-btn.active { background: #409eff; color: white; border-color: #409eff; }
        .conclusion-card { background: linear-gradient(135deg, #f5f7fa 0%, #e8f0fe 100%); padding: 20px; border-radius: 8px; border-left: 4px solid #409eff; }
        .conclusion-result { display: flex; align-items: center; gap: 10px; }
        .conclusion-label { font-size: 16px; font-weight: 500; color: #666; }
        .conclusion-value { font-size: 20px; font-weight: bold; padding: 5px 15px; border-radius: 4px; background: white; }
        .conclusion-value.risk-low { color: #67c23a; border: 2px solid #67c23a; }
        .conclusion-value.risk-high { color: #f56c6c; border: 2px solid #f56c6c; }
        .recommendations-new { margin-top: 10px; }
        .recommendations-new > ul { list-style: none; padding-left: 0; }
        .recommendations-new > ul > li { padding: 8px 0 8px 20px; position: relative; color: #666; font-size: 14px; }
        .recommendations-new > ul > li:before { content: "→"; position: absolute; left: 0; color: #409eff; font-weight: bold; }
        .priority-group { margin-bottom: 15px; border: 1px solid #e4e7ed; border-radius: 6px; overflow: hidden; }
        .priority-header { display: flex; align-items: center; padding: 12px 15px; cursor: pointer; user-select: none; transition: background-color 0.3s; gap: 10px; }
        .priority-header:hover { background-color: #f5f7fa; }
        .priority-header.priority-p0 { background: #fef0f0; border-left: 4px solid #f56c6c; }
        .priority-header.priority-p1 { background: #fdf6ec; border-left: 4px solid #e6a23c; }
        .priority-header.priority-p2 { background: #f0f9ff; border-left: 4px solid #409eff; }
        .priority-badge { font-weight: bold; font-size: 14px; padding: 3px 8px; border-radius: 3px; background: white; }
        .priority-header.priority-p0 .priority-badge { color: #f56c6c; }
        .priority-header.priority-p1 .priority-badge { color: #e6a23c; }
        .priority-header.priority-p2 .priority-badge { color: #409eff; }
        .priority-count { font-size: 13px; color: #909399; }
        .priority-toggle-icon { margin-left: auto; transition: transform 0.3s; color: #909399; }
        .priority-toggle-icon.collapsed { transform: rotate(-90deg); }
        .priority-content { list-style: none; padding: 15px 20px 15px 40px; margin: 0; background: white; max-height: 1000px; overflow: hidden; transition: max-height 0.4s ease-in-out, padding 0.4s, opacity 0.3s; opacity: 1; }
        .priority-content.collapsed { max-height: 0; padding-top: 0; padding-bottom: 0; opacity: 0; }
        .priority-content.expanded { max-height: none; }
        .priority-content li { padding: 6px 0 6px 15px; color: #606266; font-size: 14px; line-height: 1.6; position: relative; }
        .priority-content li:before { content: "•"; position: absolute; left: 0; font-weight: bold; }
        .priority-header.priority-p0 + .priority-content li:before { color: #f56c6c; }
        .priority-header.priority-p1 + .priority-content li:before { color: #e6a23c; }
        .priority-header.priority-p2 + .priority-content li:before { color: #409eff; }
        @media print { body { background: white; } .toolbar { display: none; } .container { box-shadow: none; } }
        @media (max-width: 768px) { .toolbar { flex-wrap: wrap; } .filter-group { width: 100%; margin-left: 0; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 NGINX Ingress to Higress 迁移分析报告</h1>
            <div class="meta">
                <span>生成时间: """ + generated_time + """</span> |
                <span>分析 Ingress 数量: """ + str(total_ingresses_count) + """</span>
            </div>
        </div>

        <div class="toolbar">
            <button class="btn btn-primary" onclick="saveProgress()">💾 保存进度</button>
            <button class="btn btn-success" onclick="exportReport()">📥 导出报告</button>
            <button class="btn btn-secondary" onclick="expandAll()">展开全部</button>
            <button class="btn btn-secondary" onclick="collapseAll()">收起全部</button>
            <div class="filter-group">
                <button class="filter-btn active" data-filter="all" onclick="filterIssues('all')">全部</button>
                <button class="filter-btn" data-filter="unchecked" onclick="filterIssues('unchecked')">待处理</button>
                <button class="filter-btn" data-filter="checked" onclick="filterIssues('checked')">已处理</button>
            </div>
        </div>

        <div class="section">
            <h2><span class="icon">📋</span>迁移评估结论</h2>
            <div class="conclusion-card">
                <div class="conclusion-result">
                    <span class="conclusion-label">迁移评估：</span>
                    <span class="conclusion-value """ + can_migrate_class + """">""" + recommendations_title + """</span>
                </div>
            </div>
        </div>

        <div class="section">
            <h2><span class="icon">⚡</span>待处理内容</h2>
            <div class="recommendations-new">
                """ + recommendations_html + """
            </div>
        </div>

        """ + route_priority_html + """

        <div class="section">
            <h2><span class="icon">📋</span>详细分析</h2>
            <p style="color: #666; margin-bottom: 20px;">从注解视角和 Ingress 视角两个维度查看迁移分析结果。</p>

            <div class="tab-container">
                <div class="tab-buttons">
                    <button class="tab-button active" onclick="switchTab('annotation')">🏷️ 注解视角</button>
                    <button class="tab-button" onclick="switchTab('ingress')">📦 Ingress 视角</button>
                </div>

                <div id="tab-annotation" class="tab-content active">
                    <h3><span class="icon">📊</span>注解使用统计</h3>
                    <div class="stats-grid" style="margin-bottom: 30px;">
                        """ + annotation_stats_html + """
                    </div>

                    <h3 style="color: #f56c6c; margin-bottom: 15px;">🚨 阻塞性问题汇总（共 """ + str(blocking_issues_count) + """ 个）</h3>
                    <p style="color: #666; margin-bottom: 20px;">必须处理的不兼容和未知注解。</p>
                    """ + blocking_issues_html + """

                    <h3 style="color: #409eff; margin: 30px 0 15px 0;">📋 其他注解</h3>
                    <p style="color: #666; margin-bottom: 20px;">部分兼容、可等价替换、完全兼容、无需迁移等注解。</p>
                    """ + all_annotations_html + """
                </div>

                <div id="tab-ingress" class="tab-content">
                    <h3 style="color: #409eff; margin-bottom: 15px;">按兼容性分类展示所有 Ingress（共 """ + str(total_ingresses_count) + """ 个）</h3>
                    """ + ingress_classification_html + """
                </div>
            </div>
        </div>
    </div>

    <script>
        function switchTab(tabName) {
            document.querySelectorAll('.tab-button').forEach(btn => {
                btn.classList.toggle('active',
                    (tabName === 'ingress' && btn.textContent.includes('Ingress')) ||
                    (tabName === 'annotation' && btn.textContent.includes('注解')));
            });
            document.querySelectorAll('.tab-content').forEach(c => {
                c.classList.toggle('active', c.id === 'tab-' + tabName);
            });
        }
        function toggleIngress(id) {
            var c = document.getElementById('content-' + id);
            var i = document.getElementById('icon-' + id);
            if (c.classList.contains('expanded')) { c.classList.remove('expanded'); i.classList.add('collapsed'); }
            else { c.classList.add('expanded'); i.classList.remove('collapsed'); }
        }
        function togglePriority(id) {
            var c = document.getElementById('content-' + id);
            var i = document.getElementById('toggle-' + id);
            if (c.classList.contains('expanded')) { c.classList.remove('expanded'); c.classList.add('collapsed'); i.classList.add('collapsed'); }
            else { c.classList.remove('collapsed'); c.classList.add('expanded'); i.classList.remove('collapsed'); }
        }
        function scrollToSection(sectionId) {
            if (!sectionId) return;
            var el = document.getElementById(sectionId);
            if (el) { setTimeout(function() { el.scrollIntoView({behavior:'smooth',block:'start'}); el.style.transition='background-color 0.6s'; var orig=el.style.backgroundColor; el.style.backgroundColor='#fff3cd'; setTimeout(function(){el.style.backgroundColor=orig;},1500); }, 100); }
        }
        function saveProgress() {
            var progress = {};
            document.querySelectorAll('.checkbox-wrapper input[type="checkbox"]').forEach(function(cb) {
                var id = cb.dataset.issueId || cb.dataset.ingressId;
                var ta = document.querySelector('textarea[data-issue-id="'+id+'"]') || document.querySelector('textarea[data-ingress-id="'+id+'"]');
                progress[id] = {checked: cb.checked, action: ta ? ta.value : ''};
            });
            localStorage.setItem('migration_progress_v2', JSON.stringify(progress));
            alert('✅ 进度已保存到本地');
        }
        function exportReport() {
            var blob = new Blob([document.documentElement.outerHTML], {type: 'text/html'});
            var a = document.createElement('a'); a.href = URL.createObjectURL(blob);
            a.download = 'migration-report-' + new Date().toISOString().slice(0,10) + '.html';
            a.click();
        }
        function toggleIssue(el) {
            var c = el.nextElementSibling; var i = el.querySelector('.expand-icon');
            c.classList.toggle('expanded'); i.classList.toggle('expanded');
        }
        function toggleIssueGroup(groupId) {
            var c = document.getElementById('content-' + groupId);
            var i = document.getElementById('icon-' + groupId);
            if (c.classList.contains('expanded')) { c.classList.remove('expanded'); i.classList.add('collapsed'); }
            else { c.classList.add('expanded'); i.classList.remove('collapsed'); }
        }
        function expandAll() {
            document.querySelectorAll('.issue-content').forEach(function(el){el.classList.add('expanded');});
            document.querySelectorAll('.expand-icon').forEach(function(el){el.classList.add('expanded');});
            document.querySelectorAll('.issue-group-content').forEach(function(el){el.classList.add('expanded');});
            document.querySelectorAll('.issue-group-header .group-icon').forEach(function(el){el.classList.remove('collapsed');});
            document.querySelectorAll('.priority-content').forEach(function(el){el.classList.remove('collapsed');el.classList.add('expanded');});
            document.querySelectorAll('.priority-toggle-icon').forEach(function(el){el.classList.remove('collapsed');});
        }
        function collapseAll() {
            document.querySelectorAll('.issue-content').forEach(function(el){el.classList.remove('expanded');});
            document.querySelectorAll('.expand-icon').forEach(function(el){el.classList.remove('expanded');});
            document.querySelectorAll('.issue-group-content').forEach(function(el){el.classList.remove('expanded');});
            document.querySelectorAll('.issue-group-header .group-icon').forEach(function(el){el.classList.add('collapsed');});
            document.querySelectorAll('.priority-content').forEach(function(el){el.classList.remove('expanded');el.classList.add('collapsed');});
            document.querySelectorAll('.priority-toggle-icon').forEach(function(el){el.classList.add('collapsed');});
        }
        function filterIssues(filter) {
            document.querySelectorAll('.filter-btn').forEach(function(b){b.classList.toggle('active',b.dataset.filter===filter);});
            document.querySelectorAll('.issue-item').forEach(function(item) {
                var cb = item.querySelector('input[type="checkbox"]');
                if (!cb) { item.style.display = ''; return; }
                if (filter === 'all') item.style.display = '';
                else if (filter === 'checked') item.style.display = cb.checked ? '' : 'none';
                else item.style.display = cb.checked ? 'none' : '';
            });
        }
        function copyAnnotation(btn, text) {
            navigator.clipboard.writeText(text).then(function() {
                var orig = btn.textContent; btn.textContent = '✓'; btn.classList.add('copied');
                setTimeout(function(){btn.textContent=orig;btn.classList.remove('copied');},1500);
            });
        }
        // 加载保存的进度
        (function() {
            var saved = localStorage.getItem('migration_progress_v2');
            if (saved) {
                var progress = JSON.parse(saved);
                Object.keys(progress).forEach(function(key) {
                    var cb = document.querySelector('input[data-issue-id="'+key+'"]') || document.querySelector('input[data-ingress-id="'+key+'"]');
                    if (cb) { cb.checked = progress[key].checked; }
                    var ta = document.querySelector('textarea[data-issue-id="'+key+'"]') || document.querySelector('textarea[data-ingress-id="'+key+'"]');
                    if (ta && progress[key].action) { ta.value = progress[key].action; }
                });
            }
        })();
    </script>
</body>
</html>"""

    def generate_report(self, ingresses, output_file=None, output_format='html'):
        """生成迁移分析报告"""
        print("\n" + "=" * 80)
        print("NGINX Ingress to Higress 迁移分析报告 (v2)")
        print("=" * 80)
        print(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"分析的 Ingress 数量: {len(ingresses)}")
        print(f"兼容性数据库: 130 个注解，5 种分类")
        print("=" * 80 + "\n")

        total_stats = {
            "完全兼容": 0, "可等价替换": 0, "不兼容": 0,
            "部分兼容": 0, "无需迁移": 0, "未知注解": 0
        }
        risk_stats = {"🔴 高风险": 0, "🟡 中风险": 0, "✅ 兼容": 0}

        detailed_results = []
        blocking_issues = []

        for ns_name, ing in ingresses:
            metadata = ing.get("metadata") or {}
            ing_name = metadata.get("name", "")
            annotations = metadata.get("annotations") or {}

            analysis = self.analyze_annotations(annotations)

            for key in total_stats.keys():
                total_stats[key] += len(analysis[key])

            risk_level, risk_count = self.calculate_migration_risk(analysis)
            risk_stats[risk_level] += 1

            need_attention = []

            # 不兼容注解 → 阻塞性问题
            for item in analysis["不兼容"]:
                need_attention.append(item)
                blocking_issues.append({"ingress": f"{ns_name}/{ing_name}", "type": "不兼容", **item})

            # 未知注解 → 阻塞性问题
            for item in analysis["未知注解"]:
                need_attention.append(item)
                blocking_issues.append({"ingress": f"{ns_name}/{ing_name}", "type": "未知注解", **item})

            # 部分兼容和可等价替换中的高/中风险项
            for item in analysis["部分兼容"]:
                if "高风险" in item.get("risk", "") or "中风险" in item.get("risk", ""):
                    need_attention.append(item)
            for item in analysis["可等价替换"]:
                if "高风险" in item.get("risk", "") or "中风险" in item.get("risk", ""):
                    need_attention.append(item)

            detailed_results.append({
                "namespace": ns_name, "name": ing_name,
                "risk_level": risk_level, "risk_count": risk_count,
                "analysis": analysis, "need_attention": need_attention
            })

        # 收集所有注解用于完整列表展示
        all_annotations_by_type = {
            "完全兼容": [], "可等价替换": [], "不兼容": [],
            "部分兼容": [], "无需迁移": [], "未知注解": []
        }

        # 按 Ingress 分类
        ingress_classification = {
            "完美兼容": [],
            "需改造-中风险": [],
            "需改造-高风险": []
        }

        for result in detailed_results:
            ing_identifier = f"{result['namespace']}/{result['name']}"
            analysis = result['analysis']

            has_incompatible = len(analysis.get('不兼容', [])) > 0 or len(analysis.get('未知注解', [])) > 0
            has_partial_or_replaceable = len(analysis.get('部分兼容', [])) > 0 or len(analysis.get('可等价替换', [])) > 0

            ingress_info = {
                'identifier': ing_identifier,
                'namespace': result['namespace'],
                'name': result['name'],
                'risk_level': result['risk_level'],
                'annotation_counts': {k: len(analysis.get(k, [])) for k in total_stats.keys()},
                'blocking_annotations': [],
                'attention_annotations': []
            }

            for item in analysis.get('不兼容', []):
                ingress_info['blocking_annotations'].append({
                    'type': '不兼容', 'annotation': item.get('annotation', ''), 'solution': item.get('solution', '')
                })
            for item in analysis.get('未知注解', []):
                ingress_info['blocking_annotations'].append({
                    'type': '未知注解', 'annotation': item.get('annotation', ''), 'solution': item.get('solution', '')
                })
            for item in analysis.get('可等价替换', []):
                ingress_info['attention_annotations'].append({
                    'type': '可等价替换', 'annotation': item.get('annotation', ''), 'solution': item.get('solution', '')
                })
            for item in analysis.get('部分兼容', []):
                ingress_info['attention_annotations'].append({
                    'type': '部分兼容', 'annotation': item.get('annotation', ''), 'solution': item.get('solution', '')
                })

            if has_incompatible:
                ingress_classification['需改造-高风险'].append(ingress_info)
            elif has_partial_or_replaceable:
                ingress_classification['需改造-中风险'].append(ingress_info)
            else:
                ingress_classification['完美兼容'].append(ingress_info)

            for anno_type, annotations in analysis.items():
                for anno_info in annotations:
                    existing = next((item for item in all_annotations_by_type[anno_type]
                                     if item['annotation'] == anno_info['annotation']), None)
                    if existing:
                        existing['ingresses'].append(ing_identifier)
                    else:
                        all_annotations_by_type[anno_type].append({**anno_info, 'ingresses': [ing_identifier]})

        # 控制台输出
        print(f"\n{'=' * 80}")
        print("📊 全局统计")
        print(f"{'=' * 80}")
        print(f"总 Ingress 数量: {len(ingresses)}")
        print(f"\n风险分布:")
        for risk, count in risk_stats.items():
            if count > 0:
                pct = (count / len(ingresses) * 100) if len(ingresses) > 0 else 0
                print(f"  {risk}: {count} ({pct:.1f}%)")

        print(f"\n注解使用统计:")
        total_annotations = sum(total_stats.values())
        for key, count in total_stats.items():
            if count > 0:
                pct = (count / total_annotations * 100) if total_annotations > 0 else 0
                print(f"  {key}: {count} ({pct:.1f}%)")

        if blocking_issues:
            print(f"\n{'=' * 80}")
            print("🚨 阻塞性问题汇总（必须处理）")
            print(f"{'=' * 80}")
            issues_by_type = defaultdict(list)
            for issue in blocking_issues:
                issues_by_type[issue['type']].append(issue)
            for issue_type, issues in issues_by_type.items():
                print(f"\n{issue_type} ({len(issues)} 个):")
                issues_by_anno = defaultdict(list)
                for issue in issues:
                    issues_by_anno[issue['annotation']].append(issue['ingress'])
                for anno, ings in issues_by_anno.items():
                    print(f"\n  • {anno}")
                    print(f"    影响的 Ingress ({len(ings)} 个):")
                    for ing in ings[:5]:
                        print(f"      - {ing}")
                    if len(ings) > 5:
                        print(f"      ... 还有 {len(ings) - 5} 个")
                    sample = next(i for i in issues if i['annotation'] == anno)
                    if 'solution' in sample:
                        print(f"    解决方案: {sample['solution']}")

        # 路由优先级分析
        route_priority_conflicts = self.analyze_route_priority(ingresses)
        if route_priority_conflicts:
            print(f"\n{'=' * 80}")
            print(f"🔀 路由优先级变更警告（{len(route_priority_conflicts)} 个冲突）")
            print(f"{'=' * 80}")
            print("\n  NGINX 优先级:  exact > regex > prefix (相同类型按创建时间排序)")
            print("  Higress 优先级: exact > prefix > regex (相同类型按路径长度倒序)\n")
            for i, c in enumerate(route_priority_conflicts, 1):
                print(f"  {i}. host={c['host']}:")
                print(f"     regex  路径 '{c['regex_path']}' (Ingress: {c['regex_ingress']}, 后端: {c['regex_backend']})")
                print(f"     prefix 路径 '{c['prefix_path']}' (Ingress: {c['prefix_ingress']}, 后端: {c['prefix_backend']})")
                print(f"     → NGINX 中 regex 优先，Higress 中 prefix 优先，可能导致流量变化")
                print()

        # 迁移建议
        can_migrate = risk_stats["🔴 高风险"] == 0

        print(f"\n{'=' * 80}")
        print("💡 迁移建议")
        print(f"{'=' * 80}")
        if can_migrate:
            print("\n✅ 总体评估: 可以平滑迁移")
            print("1. 处理所有「可等价替换」的注解，部署必要的 WASM 插件")
            print("2. 评估「部分兼容」注解的实际使用值是否在兼容范围内")
            print("3. 在测试环境进行完整功能测试")
            print("4. 灰度发布到生产环境")
        else:
            print(f"\n⚠️  总体评估: 存在高风险，需要重点处理后才能迁移")
            print(f"发现 {risk_stats['🔴 高风险']} 个高风险 Ingress")
            print("1. 【P0】处理 snippet 类注解，开发 WASM 插件或使用内置插件组合替代")
            print("2. 【P0】迁移 auth-type/auth-secret 到 basic-auth 插件")
            print("3. 【P0】配置 ext-auth 插件替代 auth-url 等外部认证注解")
            print("4. 【P1】部署限流、WAF 等必要的 WASM 插件")
            print("5. 【P1】调整超时配置")
            print("6. 【P2】关注 Istio API 升级后 session-cookie-samesite/secure 的支持")

        # 输出报告文件
        if output_file:
            if output_format in ['html', 'both']:
                html_file = output_file if output_file.endswith('.html') else output_file.replace('.json', '.html')
                if not html_file.endswith('.html'):
                    html_file += '.html'
                self.generate_html_report(ingresses, detailed_results, total_stats, risk_stats,
                                          blocking_issues, all_annotations_by_type, ingress_classification,
                                          can_migrate, html_file, route_priority_conflicts)

            if output_format in ['json', 'both']:
                json_file = output_file if output_file.endswith('.json') else output_file.replace('.html', '.json')
                if not json_file.endswith('.json'):
                    json_file += '.json'
                report_data = {
                    "generated_at": datetime.now().isoformat(),
                    "version": "v2",
                    "total_ingresses": len(ingresses),
                    "can_migrate_smoothly": can_migrate,
                    "compatibility_db": {
                        "total_annotations": 130,
                        "categories": ["完全兼容(41)", "可等价替换(37)", "不兼容(34)", "部分兼容(7)", "无需迁移(11)"]
                    },
                    "risk_stats": risk_stats,
                    "annotation_stats": total_stats,
                    "detailed_results": [
                        {
                            "namespace": r["namespace"], "name": r["name"],
                            "risk_level": r["risk_level"], "risk_count": r["risk_count"],
                            "need_attention_count": len(r["need_attention"]),
                            "need_attention": r["need_attention"]
                        }
                        for r in detailed_results
                    ],
                    "blocking_issues": blocking_issues,
                    "route_priority_conflicts": route_priority_conflicts
                }
                try:
                    with open(json_file, 'w', encoding='utf-8') as f:
                        json.dump(report_data, f, ensure_ascii=False, indent=2)
                    print(f"✅ JSON 报告已保存到: {json_file}")
                except Exception as e:
                    print(f"❌ 保存 JSON 报告失败: {e}")

        print("\n" + "=" * 80)
        print("分析完成")
        print("=" * 80 + "\n")

        return detailed_results, can_migrate


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='NGINX Ingress to Higress 迁移分析工具 (v2)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 使用默认 kubeconfig，生成 HTML 报告
  python nginx_ingress_migration_analyzer.py --output report.html

  # 指定 kubeconfig 文件
  python nginx_ingress_migration_analyzer.py --kubeconfig ~/.kube/config --output report.html

  # 生成 JSON 格式报告
  python nginx_ingress_migration_analyzer.py --output report.json --format json

  # 同时生成 HTML 和 JSON 报告
  python nginx_ingress_migration_analyzer.py --output report --format both
        """
    )
    parser.add_argument('--kubeconfig', type=str, help='Kubernetes 配置文件路径')
    parser.add_argument('--output', '-o', type=str, help='输出报告的文件路径')
    parser.add_argument('--format', '-f', type=str, choices=['json', 'html', 'both'], default='html',
                        help='输出格式（默认：html）')

    args = parser.parse_args()

    print("\n🚀 开始分析 NGINX Ingress 资源...\n")

    analyzer = MigrationAnalyzer(kubeconfig=args.kubeconfig)

    print("📥 正在获取集群中的 NGINX Ingress 资源...")
    ingresses = analyzer.get_all_ingresses()

    if not ingresses:
        print("\n⚠️  未发现任何 NGINX Ingress 资源")
        print("\n可能的原因:")
        print("  1. 集群中没有 NGINX Ingress 资源")
        print("  2. 当前用户没有足够的权限")
        print("  3. NGINX Ingress 使用了非标准的 ingressClassName")
        return

    print(f"✅ 发现 {len(ingresses)} 个 NGINX Ingress 资源\n")

    results, can_migrate = analyzer.generate_report(ingresses, output_file=args.output, output_format=args.format)

    sys.exit(0 if can_migrate else 1)


if __name__ == '__main__':
    main()
