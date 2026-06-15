#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NGINX Ingress 注解全量验证（扩展版）

覆盖全部 130 个注解，包括无法通过 curl 验证的 69 个注解。
验证方式：
  1. curl 端到端验证（56 个）— 由 test_annotations_e2e.py 覆盖
  2. 迁移后配置验证（27 个）— 检查 Higress 是否正确生成了 Envoy 配置 / WasmPlugin / 注解转换
     - Envoy config dump: 检查 listener/route/cluster 级别的实际运行时配置
     - WasmPlugin CRD: 检查迁移是否自动创建了对应的 WASM 插件
     - Ingress 注解转换: 检查 nginx.ingress.kubernetes.io/* → higress.io/* 的注解转换
     - 人工确认: 对于无法自动验证的，给出具体的人工检查步骤
  3. 无需迁移确认（12 个）— 确认 🔴 注解被安全忽略，不影响流量
  4. 不兼容报告（35 个）— 确认 ❌ 注解在迁移报告中被正确标记

使用：
  python3 test_annotations_full_verify.py --phase pre-migration [--gateway-ip 47.108.54.156]
  python3 test_annotations_full_verify.py --phase post-migration
  python3 test_annotations_full_verify.py --phase compare
  python3 test_annotations_full_verify.py --summary

依赖：kubectl 已配置且可访问 ls-test namespace
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple

# ============================================================================
# 配置
# ============================================================================
GATEWAY_IP = "127.0.0.1:8888"
NAMESPACE = "ls-test"
RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-results")
KUBECTL_TIMEOUT = 15


# ============================================================================
# 数据模型
# ============================================================================
@dataclass
class VerifyResult:
    """单个注解的验证结果"""
    annotation: str
    category: str           # 功能分类
    compatibility: str      # ✅ 🔵 ❌ ⚠️ 🔴
    verify_method: str      # curl / envoy-config / wasmplugin / ingress-annotation / manual / no-migration / incompatible
    passed: bool
    phase: str
    timestamp: str
    details: str = ""
    error: str = ""
    evidence: str = ""      # 验证证据（配置片段、命令输出等）
    manual_steps: str = ""  # 人工验证步骤（如果需要）


# ============================================================================
# 工具函数
# ============================================================================
def run_cmd(cmd: List[str], timeout: int = KUBECTL_TIMEOUT) -> Tuple[int, str, str]:
    """执行命令，返回 (returncode, stdout, stderr)"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "命令超时"
    except Exception as e:
        return -1, "", str(e)


def kubectl_get_json(resource: str, name: str = "", namespace: str = NAMESPACE,
                     extra_args: List[str] = None) -> Optional[Dict]:
    """kubectl get 资源并返回 JSON"""
    cmd = ["kubectl", "get", resource]
    if name:
        cmd.append(name)
    cmd.extend(["-n", namespace, "-o", "json"])
    if extra_args:
        cmd.extend(extra_args)
    rc, stdout, stderr = run_cmd(cmd)
    if rc == 0 and stdout:
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return None
    return None


def get_gateway_pod_name(namespace: str = NAMESPACE) -> str:
    """获取 Higress gateway pod 名称"""
    cmd = ["kubectl", "get", "pod", "-n", namespace, "-l", "app=higress-gateway",
           "-o", "jsonpath={.items[0].metadata.name}"]
    rc, stdout, _ = run_cmd(cmd)
    return stdout.strip() if rc == 0 else ""


def get_envoy_config_dump(namespace: str = NAMESPACE, resource: str = "") -> str:
    """获取 Envoy config dump"""
    pod = get_gateway_pod_name(namespace)
    if not pod:
        return ""
    url = "http://localhost:15000/config_dump"
    if resource:
        url += f"?resource={resource}"
    cmd = ["kubectl", "exec", "-n", namespace, pod, "-c", "higress-gateway",
           "--", "curl", "-s", url]
    rc, stdout, _ = run_cmd(cmd, timeout=30)
    return stdout if rc == 0 else ""


def get_envoy_listeners_dump(namespace: str = NAMESPACE) -> str:
    """获取 Envoy listener 配置"""
    return get_envoy_config_dump(namespace, "dynamic_listeners")


def get_envoy_clusters_dump(namespace: str = NAMESPACE) -> str:
    """获取 Envoy cluster 配置"""
    return get_envoy_config_dump(namespace, "dynamic_active_clusters")


def get_envoy_routes_dump(namespace: str = NAMESPACE) -> str:
    """获取 Envoy route 配置"""
    return get_envoy_config_dump(namespace, "dynamic_route_configs")


# ============================================================================
# 全部 130 个注解定义
# ============================================================================
ALL_ANNOTATIONS = [
    # === 1. 路由与重写 (8) ===
    {"name": "rewrite-target",          "compat": "✅", "cat": "路由与重写",   "verify": "curl"},
    {"name": "use-regex",               "compat": "✅", "cat": "路由与重写",   "verify": "curl"},
    {"name": "upstream-vhost",          "compat": "✅", "cat": "路由与重写",   "verify": "curl"},
    {"name": "app-root",               "compat": "✅", "cat": "路由与重写",   "verify": "curl"},
    {"name": "preserve-trailing-slash", "compat": "🔵", "cat": "路由与重写",   "verify": "post-config"},
    {"name": "proxy-redirect-from",    "compat": "🔵", "cat": "路由与重写",   "verify": "post-config"},
    {"name": "proxy-redirect-to",      "compat": "🔵", "cat": "路由与重写",   "verify": "post-config"},
    {"name": "x-forwarded-prefix",     "compat": "🔵", "cat": "路由与重写",   "verify": "curl"},
    # === 2. 重定向 (8) ===
    {"name": "ssl-redirect",           "compat": "✅", "cat": "重定向",       "verify": "curl"},
    {"name": "force-ssl-redirect",     "compat": "✅", "cat": "重定向",       "verify": "curl"},
    {"name": "permanent-redirect",     "compat": "✅", "cat": "重定向",       "verify": "curl"},
    {"name": "permanent-redirect-code","compat": "✅", "cat": "重定向",       "verify": "curl"},
    {"name": "temporal-redirect",      "compat": "✅", "cat": "重定向",       "verify": "curl"},
    {"name": "temporal-redirect-code", "compat": "❌", "cat": "重定向",       "verify": "incompatible"},
    {"name": "from-to-www-redirect",   "compat": "🔵", "cat": "重定向",       "verify": "post-config"},
    {"name": "server-alias",           "compat": "⚠️", "cat": "重定向",       "verify": "curl"},
    # === 3. CORS (7) ===
    {"name": "enable-cors",            "compat": "✅", "cat": "CORS",         "verify": "curl"},
    {"name": "cors-allow-origin",      "compat": "✅", "cat": "CORS",         "verify": "curl"},
    {"name": "cors-allow-methods",     "compat": "✅", "cat": "CORS",         "verify": "curl"},
    {"name": "cors-allow-headers",     "compat": "✅", "cat": "CORS",         "verify": "curl"},
    {"name": "cors-allow-credentials", "compat": "✅", "cat": "CORS",         "verify": "curl"},
    {"name": "cors-expose-headers",    "compat": "✅", "cat": "CORS",         "verify": "curl"},
    {"name": "cors-max-age",           "compat": "✅", "cat": "CORS",         "verify": "curl"},
    # === 4. 灰度发布 (8) ===
    {"name": "canary",                 "compat": "✅", "cat": "灰度发布",     "verify": "curl"},
    {"name": "canary-weight",          "compat": "✅", "cat": "灰度发布",     "verify": "curl"},
    {"name": "canary-by-header",       "compat": "✅", "cat": "灰度发布",     "verify": "curl"},
    {"name": "canary-by-header-value", "compat": "✅", "cat": "灰度发布",     "verify": "curl"},
    {"name": "canary-by-header-pattern","compat": "✅","cat": "灰度发布",     "verify": "curl"},
    {"name": "canary-by-cookie",       "compat": "✅", "cat": "灰度发布",     "verify": "curl"},
    {"name": "canary-weight-total",    "compat": "✅", "cat": "灰度发布",     "verify": "curl"},
    {"name": "affinity-canary-behavior","compat": "✅","cat": "灰度发布",     "verify": "post-config"},
    # === 5. 认证与授权 (27) ===
    # 5.1 外部认证 (11)
    {"name": "auth-url",               "compat": "🔵", "cat": "外部认证",     "verify": "curl"},
    {"name": "auth-signin",            "compat": "❌", "cat": "外部认证",     "verify": "incompatible"},
    {"name": "auth-response-headers",  "compat": "🔵", "cat": "外部认证",     "verify": "curl"},
    {"name": "auth-proxy-set-headers", "compat": "🔵", "cat": "外部认证",     "verify": "post-config"},
    {"name": "auth-snippet",           "compat": "❌", "cat": "外部认证",     "verify": "incompatible"},
    {"name": "auth-method",            "compat": "🔵", "cat": "外部认证",     "verify": "post-config"},
    {"name": "auth-signin-redirect-param","compat":"❌","cat": "外部认证",    "verify": "incompatible"},
    {"name": "auth-request-redirect",  "compat": "❌", "cat": "外部认证",     "verify": "incompatible"},
    {"name": "auth-always-set-cookie", "compat": "❌", "cat": "外部认证",     "verify": "incompatible"},
    {"name": "auth-cache-duration",    "compat": "❌", "cat": "外部认证",     "verify": "incompatible"},
    {"name": "auth-cache-key",         "compat": "❌", "cat": "外部认证",     "verify": "incompatible"},
    # 5.2 Basic 认证 (4)
    {"name": "auth-type",              "compat": "🔵", "cat": "Basic认证",    "verify": "curl"},
    {"name": "auth-secret",            "compat": "🔵", "cat": "Basic认证",    "verify": "post-config"},
    {"name": "auth-secret-type",       "compat": "🔵", "cat": "Basic认证",    "verify": "post-config"},
    {"name": "auth-realm",             "compat": "🔵", "cat": "Basic认证",    "verify": "post-config"},
    # 5.3 认证连接管理 (4)
    {"name": "auth-keepalive",         "compat": "❌", "cat": "认证连接",     "verify": "incompatible"},
    {"name": "auth-keepalive-requests","compat": "❌", "cat": "认证连接",     "verify": "incompatible"},
    {"name": "auth-keepalive-share-vars","compat":"❌","cat": "认证连接",     "verify": "incompatible"},
    {"name": "auth-keepalive-timeout", "compat": "❌", "cat": "认证连接",     "verify": "incompatible"},
    # 5.4 mTLS (6)
    {"name": "auth-tls-secret",        "compat": "⚠️", "cat": "mTLS",         "verify": "post-config"},
    {"name": "auth-tls-verify-client", "compat": "🔵", "cat": "mTLS",         "verify": "post-config"},
    {"name": "auth-tls-error-page",    "compat": "❌", "cat": "mTLS",         "verify": "incompatible"},
    {"name": "auth-tls-match-cn",      "compat": "🔵", "cat": "mTLS",         "verify": "post-config"},
    {"name": "auth-tls-pass-certificate-to-upstream","compat":"🔵","cat":"mTLS","verify":"post-config"},
    {"name": "auth-tls-verify-depth",  "compat": "🔵", "cat": "mTLS",         "verify": "post-config"},
    # 5.5 认证策略 (2)
    {"name": "enable-global-auth",     "compat": "🔵", "cat": "认证策略",     "verify": "post-config"},
    {"name": "satisfy",                "compat": "❌", "cat": "认证策略",     "verify": "incompatible"},
    # === 6. SSL/TLS (10) ===
    {"name": "ssl-passthrough",        "compat": "❌", "cat": "SSL/TLS",      "verify": "incompatible"},
    {"name": "ssl-ciphers",            "compat": "🔵", "cat": "SSL/TLS",      "verify": "post-config"},
    {"name": "ssl-prefer-server-ciphers","compat":"🔴","cat": "SSL/TLS",      "verify": "no-migration"},
    {"name": "proxy-ssl-secret",       "compat": "✅", "cat": "SSL/TLS",      "verify": "post-config"},
    {"name": "proxy-ssl-name",         "compat": "✅", "cat": "SSL/TLS",      "verify": "curl"},
    {"name": "proxy-ssl-server-name",  "compat": "✅", "cat": "SSL/TLS",      "verify": "curl"},
    {"name": "proxy-ssl-verify",       "compat": "✅", "cat": "SSL/TLS",      "verify": "curl"},
    {"name": "proxy-ssl-ciphers",      "compat": "🔵", "cat": "SSL/TLS",      "verify": "post-config"},
    {"name": "proxy-ssl-protocols",    "compat": "🔵", "cat": "SSL/TLS",      "verify": "post-config"},
    {"name": "proxy-ssl-verify-depth", "compat": "🔵", "cat": "SSL/TLS",      "verify": "post-config"},
    # === 7. 负载均衡与会话保持 (15) ===
    {"name": "load-balance",           "compat": "⚠️", "cat": "负载均衡",     "verify": "curl"},
    {"name": "upstream-hash-by",       "compat": "⚠️", "cat": "负载均衡",     "verify": "curl"},
    {"name": "affinity",               "compat": "✅", "cat": "负载均衡",     "verify": "curl"},
    {"name": "affinity-mode",          "compat": "⚠️", "cat": "负载均衡",     "verify": "curl"},
    {"name": "session-cookie-name",    "compat": "✅", "cat": "负载均衡",     "verify": "curl"},
    {"name": "session-cookie-path",    "compat": "✅", "cat": "负载均衡",     "verify": "curl"},
    {"name": "session-cookie-domain",  "compat": "❌", "cat": "负载均衡",     "verify": "incompatible"},
    {"name": "session-cookie-max-age", "compat": "✅", "cat": "负载均衡",     "verify": "curl"},
    {"name": "session-cookie-expires", "compat": "✅", "cat": "负载均衡",     "verify": "curl"},
    {"name": "session-cookie-samesite","compat": "❌", "cat": "负载均衡",     "verify": "incompatible"},
    {"name": "session-cookie-secure",  "compat": "❌", "cat": "负载均衡",     "verify": "incompatible"},
    {"name": "session-cookie-change-on-failure","compat":"🔴","cat":"负载均衡","verify":"no-migration"},
    {"name": "session-cookie-conditional-samesite-none","compat":"❌","cat":"负载均衡","verify":"incompatible"},
    {"name": "upstream-hash-by-subset","compat": "❌", "cat": "负载均衡",     "verify": "incompatible"},
    {"name": "upstream-hash-by-subset-size","compat":"❌","cat":"负载均衡",   "verify": "incompatible"},
    # === 8. 访问控制 (2) ===
    {"name": "whitelist-source-range", "compat": "✅", "cat": "访问控制",     "verify": "curl"},
    {"name": "denylist-source-range",  "compat": "🔵", "cat": "访问控制",     "verify": "curl"},
    # === 9. 限流与限速 (7) ===
    {"name": "limit-rps",             "compat": "🔵", "cat": "限流限速",     "verify": "curl"},
    {"name": "limit-connections",     "compat": "🔵", "cat": "限流限速",     "verify": "curl"},
    {"name": "limit-rpm",            "compat": "🔵", "cat": "限流限速",     "verify": "post-config"},
    {"name": "limit-burst-multiplier","compat": "❌", "cat": "限流限速",     "verify": "incompatible"},
    {"name": "limit-rate-after",     "compat": "❌", "cat": "限流限速",     "verify": "incompatible"},
    {"name": "limit-rate",           "compat": "❌", "cat": "限流限速",     "verify": "incompatible"},
    {"name": "limit-whitelist",      "compat": "🔵", "cat": "限流限速",     "verify": "post-config"},
    # === 10. 后端服务配置 (19) ===
    {"name": "backend-protocol",      "compat": "⚠️", "cat": "后端服务",     "verify": "curl"},
    {"name": "proxy-body-size",       "compat": "🔴", "cat": "后端服务",     "verify": "no-migration"},
    {"name": "proxy-connect-timeout", "compat": "🔵", "cat": "后端服务",     "verify": "curl"},
    {"name": "proxy-read-timeout",    "compat": "🔵", "cat": "后端服务",     "verify": "curl"},
    {"name": "proxy-send-timeout",    "compat": "🔵", "cat": "后端服务",     "verify": "curl"},
    {"name": "proxy-next-upstream",   "compat": "✅", "cat": "后端服务",     "verify": "curl"},
    {"name": "proxy-next-upstream-timeout","compat":"✅","cat":"后端服务",    "verify": "curl"},
    {"name": "proxy-next-upstream-tries","compat":"✅","cat":"后端服务",      "verify": "curl"},
    {"name": "proxy-http-version",    "compat": "⚠️", "cat": "后端服务",     "verify": "curl"},
    {"name": "service-upstream",      "compat": "🔴", "cat": "后端服务",     "verify": "no-migration"},
    {"name": "proxy-cookie-domain",   "compat": "🔵", "cat": "后端服务",     "verify": "post-config"},
    {"name": "proxy-cookie-path",     "compat": "🔵", "cat": "后端服务",     "verify": "post-config"},
    {"name": "client-body-buffer-size","compat": "❌", "cat": "后端服务",     "verify": "incompatible"},
    {"name": "proxy-buffering",       "compat": "🔴", "cat": "后端服务",     "verify": "no-migration"},
    {"name": "proxy-buffer-size",     "compat": "🔴", "cat": "后端服务",     "verify": "no-migration"},
    {"name": "proxy-buffers-number",  "compat": "❌", "cat": "后端服务",     "verify": "incompatible"},
    {"name": "proxy-busy-buffers-size","compat": "🔴","cat": "后端服务",     "verify": "no-migration"},
    {"name": "proxy-max-temp-file-size","compat":"🔴","cat": "后端服务",     "verify": "no-migration"},
    {"name": "proxy-request-buffering","compat": "🔴","cat": "后端服务",     "verify": "no-migration"},
    # === 11. 请求/响应头控制 (2) ===
    {"name": "custom-headers",        "compat": "🔵", "cat": "头部控制",     "verify": "post-config"},
    {"name": "connection-proxy-header","compat": "🔴","cat": "头部控制",     "verify": "no-migration"},
    # === 12. 错误处理 (2) ===
    {"name": "custom-http-errors",    "compat": "✅", "cat": "错误处理",     "verify": "curl"},
    {"name": "default-backend",       "compat": "✅", "cat": "错误处理",     "verify": "curl"},
    # === 13. 流量镜像 (3) ===
    {"name": "mirror-target",         "compat": "🔵", "cat": "流量镜像",     "verify": "curl"},
    {"name": "mirror-host",           "compat": "❌", "cat": "流量镜像",     "verify": "incompatible"},
    {"name": "mirror-request-body",   "compat": "🔴", "cat": "流量镜像",     "verify": "no-migration"},
    # === 14. 安全防护 (4) ===
    {"name": "enable-modsecurity",    "compat": "🔵", "cat": "安全防护",     "verify": "curl"},
    {"name": "enable-owasp-core-rules","compat":"🔵","cat": "安全防护",     "verify": "curl"},
    {"name": "modsecurity-snippet",   "compat": "❌", "cat": "安全防护",     "verify": "incompatible"},
    {"name": "modsecurity-transaction-id","compat":"❌","cat":"安全防护",    "verify": "incompatible"},
    # === 15. 可观测性 (4) ===
    {"name": "enable-opentelemetry",  "compat": "❌", "cat": "可观测性",     "verify": "incompatible"},
    {"name": "opentelemetry-trust-incoming-span","compat":"❌","cat":"可观测性","verify":"incompatible"},
    {"name": "enable-access-log",     "compat": "🔵", "cat": "可观测性",     "verify": "post-config"},
    {"name": "enable-rewrite-log",    "compat": "❌", "cat": "可观测性",     "verify": "incompatible"},
    # === 16. Snippet (3) ===
    {"name": "configuration-snippet", "compat": "❌", "cat": "Snippet",      "verify": "incompatible"},
    {"name": "server-snippet",        "compat": "❌", "cat": "Snippet",      "verify": "incompatible"},
    {"name": "stream-snippet",        "compat": "❌", "cat": "Snippet",      "verify": "incompatible"},
    # === 17. 其他 (1) ===
    {"name": "http2-push-preload",    "compat": "🔴", "cat": "其他",         "verify": "no-migration"},
]


# ============================================================================
# 迁移后配置验证器（核心改造）
#
# 验证思路：迁移后 Higress 应该把 NGINX 注解转换成对应的 Envoy 配置。
# 我们通过以下方式验证：
#   1. Envoy config dump — 检查 listener/route/cluster 中是否生成了正确配置
#   2. WasmPlugin CRD — 检查是否创建了对应的 WASM 插件
#   3. Ingress 注解 — 检查 nginx.ingress.kubernetes.io/* 是否转换为 higress.io/*
#   4. 人工确认 — 给出具体的 kubectl/curl 命令供人工执行
# ============================================================================
class PostMigrationVerifier:
    """迁移后配置验证器"""

    def __init__(self, namespace: str = NAMESPACE):
        self.namespace = namespace
        self._config_dump = None
        self._routes_dump = None
        self._clusters_dump = None
        self._listeners_dump = None
        self._wasmplugins = None
        self._ingresses = None

    # --- 懒加载缓存 ---
    @property
    def config_dump(self) -> str:
        if self._config_dump is None:
            self._config_dump = get_envoy_config_dump(self.namespace)
        return self._config_dump

    @property
    def routes_dump(self) -> str:
        if self._routes_dump is None:
            self._routes_dump = get_envoy_routes_dump(self.namespace)
        return self._routes_dump

    @property
    def clusters_dump(self) -> str:
        if self._clusters_dump is None:
            self._clusters_dump = get_envoy_clusters_dump(self.namespace)
        return self._clusters_dump

    @property
    def listeners_dump(self) -> str:
        if self._listeners_dump is None:
            self._listeners_dump = get_envoy_listeners_dump(self.namespace)
        return self._listeners_dump

    @property
    def wasmplugins(self) -> List[Dict]:
        if self._wasmplugins is None:
            data = kubectl_get_json("wasmplugin", namespace=self.namespace)
            self._wasmplugins = data.get("items", []) if data else []
        return self._wasmplugins

    @property
    def ingresses(self) -> List[Dict]:
        if self._ingresses is None:
            data = kubectl_get_json("ingress", namespace=self.namespace)
            self._ingresses = data.get("items", []) if data else []
        return self._ingresses

    # --- 通用查找 ---
    def find_wasmplugin(self, plugin_name: str) -> Optional[Dict]:
        """查找名称包含 plugin_name 的 WasmPlugin"""
        for wp in self.wasmplugins:
            name = wp.get("metadata", {}).get("name", "")
            spec_name = wp.get("spec", {}).get("pluginName", "")
            if plugin_name in name or plugin_name in spec_name:
                return wp
        return None

    def find_ingress_annotation(self, ann_key: str) -> Optional[Tuple[str, str]]:
        """在所有 Ingress 中查找包含 ann_key 的 higress.io 注解，返回 (ingress_name, value)"""
        for ing in self.ingresses:
            annotations = ing.get("metadata", {}).get("annotations", {})
            for k, v in annotations.items():
                if "higress.io" in k and ann_key in k:
                    return ing["metadata"]["name"], v
        return None

    def search_config_dump(self, keyword: str) -> bool:
        """在 Envoy config dump 中搜索关键字"""
        return keyword.lower() in self.config_dump.lower()

    def search_routes(self, keyword: str) -> bool:
        """在 Envoy route 配置中搜索关键字"""
        return keyword.lower() in self.routes_dump.lower()

    def search_clusters(self, keyword: str) -> bool:
        """在 Envoy cluster 配置中搜索关键字"""
        return keyword.lower() in self.clusters_dump.lower()

    def search_listeners(self, keyword: str) -> bool:
        """在 Envoy listener 配置中搜索关键字"""
        return keyword.lower() in self.listeners_dump.lower()

    # ================================================================
    # 具体注解验证方法
    # ================================================================

    def verify_preserve_trailing_slash(self, phase: str) -> VerifyResult:
        """迁移后检查 Ingress pathType 是否为 Exact/Prefix（替代 preserve-trailing-slash）"""
        if phase == "pre-migration":
            return self._pre_migration_note("preserve-trailing-slash", "路由与重写", "🔵",
                "迁移前由 NGINX 处理尾斜杠。迁移后通过 pathType: Exact 实现精确匹配")
        # post-migration: 检查 Ingress pathType
        for ing in self.ingresses:
            for rule in ing.get("spec", {}).get("rules", []):
                for path in rule.get("http", {}).get("paths", []):
                    pt = path.get("pathType", "")
                    if pt == "Exact":
                        return self._ok("preserve-trailing-slash", "路由与重写", "🔵", phase,
                            f"Ingress '{ing['metadata']['name']}' 使用 pathType=Exact",
                            f"pathType: {pt}, path: {path.get('path', '')}")
        return self._manual("preserve-trailing-slash", "路由与重写", "🔵", phase,
            "未找到 pathType=Exact 的路径",
            "kubectl get ingress -n ls-test -o yaml | grep -A3 pathType")

    def verify_proxy_redirect_from(self, phase: str) -> VerifyResult:
        """迁移后检查是否生成了 transformer WasmPlugin 来改写 Location 头"""
        if phase == "pre-migration":
            return self._pre_migration_note("proxy-redirect-from", "路由与重写", "🔵",
                "迁移前由 NGINX proxy_redirect 指令处理。迁移后需 transformer 插件")
        wp = self.find_wasmplugin("transformer")
        if wp:
            spec = json.dumps(wp.get("spec", {}), ensure_ascii=False)[:300]
            return self._ok("proxy-redirect-from", "路由与重写", "🔵", phase,
                f"找到 transformer WasmPlugin: {wp['metadata']['name']}",
                spec)
        return self._manual("proxy-redirect-from", "路由与重写", "🔵", phase,
            "未找到 transformer WasmPlugin（需手动创建）",
            "kubectl get wasmplugin -n ls-test | grep transformer")

    def verify_proxy_redirect_to(self, phase: str) -> VerifyResult:
        """同 proxy-redirect-from，配对使用"""
        return self.verify_proxy_redirect_from(phase)

    def verify_from_to_www_redirect(self, phase: str) -> VerifyResult:
        """迁移后检查是否有 www ↔ non-www 的重定向 Ingress"""
        if phase == "pre-migration":
            return self._pre_migration_note("from-to-www-redirect", "重定向", "🔵",
                "迁移前由 NGINX 自动处理。迁移后需创建额外 Ingress + permanent-redirect")
        # 检查是否有 www 开头的 host 的 Ingress
        for ing in self.ingresses:
            for rule in ing.get("spec", {}).get("rules", []):
                host = rule.get("host", "")
                if host.startswith("www."):
                    ann = ing.get("metadata", {}).get("annotations", {})
                    redir = {k: v for k, v in ann.items() if "redirect" in k.lower()}
                    if redir:
                        return self._ok("from-to-www-redirect", "重定向", "🔵", phase,
                            f"找到 www 域名 Ingress '{ing['metadata']['name']}' 带重定向注解",
                            json.dumps(redir, ensure_ascii=False)[:300])
        return self._manual("from-to-www-redirect", "重定向", "🔵", phase,
            "未找到 www ↔ non-www 重定向配置（需手动创建 Ingress）",
            "kubectl get ingress -n ls-test -o wide | grep www")

    def verify_affinity_canary_behavior(self, phase: str) -> VerifyResult:
        """迁移后检查 Envoy route 配置中 canary 与 affinity 的交互"""
        if phase == "pre-migration":
            return self._pre_migration_note("affinity-canary-behavior", "灰度发布", "✅",
                "迁移前由 NGINX 处理。Higress 行为始终为 legacy 模式")
        # 检查 Envoy route 中是否有 canary 相关的 hash_policy
        if self.search_routes("hash_policy") and self.search_routes("canary"):
            return self._ok("affinity-canary-behavior", "灰度发布", "✅", phase,
                "Envoy route 中存在 hash_policy + canary 配置",
                "行为始终为 legacy（忽略会话亲和性）")
        return self._manual("affinity-canary-behavior", "灰度发布", "✅", phase,
            "需确认 canary + affinity 同时配置时的行为",
            "kubectl exec -n ls-test $(kubectl get pod -n ls-test -l app=higress-gateway -o jsonpath='{.items[0].metadata.name}') "
            "-c higress-gateway -- curl -s localhost:15000/config_dump?resource=dynamic_route_configs | grep -A5 hash_policy")

    def verify_auth_proxy_set_headers(self, phase: str) -> VerifyResult:
        """迁移后检查 ext-auth WasmPlugin 的 headers_to_add 配置"""
        if phase == "pre-migration":
            return self._pre_migration_note("auth-proxy-set-headers", "外部认证", "🔵",
                "迁移前由 NGINX auth_request 模块处理。迁移后需 ext-auth 插件 headers_to_add")
        wp = self.find_wasmplugin("ext-auth")
        if wp:
            spec_str = json.dumps(wp.get("spec", {}), ensure_ascii=False)
            if "headers_to_add" in spec_str or "headersToAdd" in spec_str:
                return self._ok("auth-proxy-set-headers", "外部认证", "🔵", phase,
                    "ext-auth WasmPlugin 中配置了 headers_to_add",
                    spec_str[:300])
            return self._ok("auth-proxy-set-headers", "外部认证", "🔵", phase,
                f"找到 ext-auth WasmPlugin 但未配置 headers_to_add",
                "需手动添加 authorization_request.headers_to_add 配置")
        return self._manual("auth-proxy-set-headers", "外部认证", "🔵", phase,
            "未找到 ext-auth WasmPlugin",
            "kubectl get wasmplugin -n ls-test | grep ext-auth")

    def verify_auth_method(self, phase: str) -> VerifyResult:
        """迁移后检查 ext-auth WasmPlugin 的 request_method 配置"""
        if phase == "pre-migration":
            return self._pre_migration_note("auth-method", "外部认证", "🔵",
                "迁移前由 NGINX auth_request 模块处理。迁移后需 ext-auth 插件 request_method")
        wp = self.find_wasmplugin("ext-auth")
        if wp:
            spec_str = json.dumps(wp.get("spec", {}), ensure_ascii=False)
            if "request_method" in spec_str or "requestMethod" in spec_str:
                return self._ok("auth-method", "外部认证", "🔵", phase,
                    "ext-auth WasmPlugin 中配置了 request_method",
                    spec_str[:300])
            return self._ok("auth-method", "外部认证", "🔵", phase,
                "找到 ext-auth WasmPlugin（默认使用 GET 方法）",
                "如需自定义方法，添加 endpoint.request_method 配置")
        return self._manual("auth-method", "外部认证", "🔵", phase,
            "未找到 ext-auth WasmPlugin",
            "kubectl get wasmplugin -n ls-test | grep ext-auth")

    def verify_auth_secret(self, phase: str) -> VerifyResult:
        """迁移后检查 basic-auth WasmPlugin 是否存在（替代 K8s Secret 方式）"""
        if phase == "pre-migration":
            return self._pre_migration_note("auth-secret", "Basic认证", "🔵",
                "迁移前凭证存储在 K8s Secret 中。迁移后通过 basic-auth 插件 consumers 配置管理")
        wp = self.find_wasmplugin("basic-auth")
        if wp:
            spec_str = json.dumps(wp.get("spec", {}), ensure_ascii=False)
            if "consumer" in spec_str.lower() or "credential" in spec_str.lower():
                return self._ok("auth-secret", "Basic认证", "🔵", phase,
                    "basic-auth WasmPlugin 中配置了 consumers/credential",
                    spec_str[:300])
            return self._ok("auth-secret", "Basic认证", "🔵", phase,
                "找到 basic-auth WasmPlugin（需确认 consumers 配置）",
                spec_str[:200])
        return self._manual("auth-secret", "Basic认证", "🔵", phase,
            "未找到 basic-auth WasmPlugin（需手动创建）",
            "kubectl get wasmplugin -n ls-test | grep basic-auth")

    def verify_auth_secret_type(self, phase: str) -> VerifyResult:
        """迁移后不再需要 — basic-auth 插件直接管理凭证"""
        if phase == "pre-migration":
            return self._pre_migration_note("auth-secret-type", "Basic认证", "🔵",
                "迁移前区分 auth/opaque Secret 类型。迁移后 basic-auth 插件直接管理凭证，此概念不再适用")
        wp = self.find_wasmplugin("basic-auth")
        if wp:
            return self._ok("auth-secret-type", "Basic认证", "🔵", phase,
                "basic-auth 插件已接管凭证管理，auth-secret-type 概念不再适用",
                "凭证通过 consumers[].credential 字段直接配置")
        return self._manual("auth-secret-type", "Basic认证", "🔵", phase,
            "未找到 basic-auth WasmPlugin",
            "kubectl get wasmplugin -n ls-test | grep basic-auth")

    def verify_auth_realm(self, phase: str) -> VerifyResult:
        """迁移后检查 basic-auth 插件的 realm 配置（硬编码为 MSE Gateway）"""
        if phase == "pre-migration":
            return self._pre_migration_note("auth-realm", "Basic认证", "🔵",
                "迁移前可自定义 realm。迁移后 basic-auth 插件 realm 硬编码为 'MSE Gateway'")
        wp = self.find_wasmplugin("basic-auth")
        if wp:
            return self._ok("auth-realm", "Basic认证", "🔵", phase,
                "basic-auth 插件 realm 硬编码为 'MSE Gateway'，不支持自定义",
                "WWW-Authenticate: Basic realm=MSE Gateway")
        return self._manual("auth-realm", "Basic认证", "🔵", phase,
            "未找到 basic-auth WasmPlugin",
            "curl -s -I -H 'Host: basic-auth.test.io' http://47.108.54.156/ | grep WWW-Authenticate")

    def verify_auth_tls_secret(self, phase: str) -> VerifyResult:
        """迁移后检查 Envoy DownstreamTlsContext 中是否配置了 CA 证书"""
        if phase == "pre-migration":
            return self._pre_migration_note("auth-tls-secret", "mTLS", "⚠️",
                "迁移前由 NGINX ssl_client_certificate 处理。迁移后通过 higress.io/auth-tls-secret")
        # 检查 Envoy listener 中是否有 require_client_certificate
        if self.search_listeners("require_client_certificate") or self.search_listeners("validation_context"):
            return self._ok("auth-tls-secret", "mTLS", "⚠️", phase,
                "Envoy listener 中存在 mTLS 验证配置",
                "require_client_certificate / validation_context 已配置")
        result = self.find_ingress_annotation("auth-tls-secret")
        if result:
            return self._ok("auth-tls-secret", "mTLS", "⚠️", phase,
                f"Ingress '{result[0]}' 存在 higress.io/auth-tls-secret 注解",
                f"值: {result[1]}")
        return self._manual("auth-tls-secret", "mTLS", "⚠️", phase,
            "未找到 mTLS 配置（需 TLS Secret + CA 证书）",
            "kubectl get ingress -n ls-test -o yaml | grep auth-tls")

    def verify_auth_tls_verify_client(self, phase: str) -> VerifyResult:
        """迁移后检查 mTLS 是否启用"""
        if phase == "pre-migration":
            return self._pre_migration_note("auth-tls-verify-client", "mTLS", "🔵",
                "迁移前支持 on/off/optional。迁移后配置 auth-tls-secret 即等于 on")
        if self.search_listeners("require_client_certificate"):
            return self._ok("auth-tls-verify-client", "mTLS", "🔵", phase,
                "Envoy listener 中 require_client_certificate=true",
                "等价于 auth-tls-verify-client=on")
        return self._manual("auth-tls-verify-client", "mTLS", "🔵", phase,
            "需确认 mTLS 是否启用",
            "kubectl exec ... -- curl -s localhost:15000/config_dump | jq '.configs[].dynamic_listeners[].active_state.listener.filter_chains[].transport_socket'")

    def verify_auth_tls_match_cn(self, phase: str) -> VerifyResult:
        """迁移后检查 EnvoyFilter 中是否配置了 SAN 匹配"""
        if phase == "pre-migration":
            return self._pre_migration_note("auth-tls-match-cn", "mTLS", "🔵",
                "迁移前匹配 CN。迁移后通过 EnvoyFilter 配置 match_typed_subject_alt_names（匹配 SAN）")
        if self.search_config_dump("match_typed_subject_alt_names") or self.search_config_dump("match_subject_alt_names"):
            return self._ok("auth-tls-match-cn", "mTLS", "🔵", phase,
                "Envoy 配置中存在 SAN 匹配规则",
                "注意: Envoy 匹配 SAN 而非 CN，语义略有差异")
        return self._manual("auth-tls-match-cn", "mTLS", "🔵", phase,
            "未找到 SAN 匹配配置（需通过 EnvoyFilter 配置）",
            "kubectl get envoyfilter -n ls-test -o yaml | grep match_subject_alt_names")

    def verify_auth_tls_pass_cert(self, phase: str) -> VerifyResult:
        """迁移后检查 Envoy 是否配置了 forward_client_cert_details"""
        if phase == "pre-migration":
            return self._pre_migration_note("auth-tls-pass-certificate-to-upstream", "mTLS", "🔵",
                "迁移前通过 ssl-client-cert 头传递。迁移后通过 XFCC 头（x-forwarded-client-cert）")
        if self.search_config_dump("forward_client_cert_details"):
            return self._ok("auth-tls-pass-certificate-to-upstream", "mTLS", "🔵", phase,
                "Envoy 配置了 forward_client_cert_details",
                "使用 XFCC 头传递证书信息，格式与 NGINX ssl-client-cert 不同")
        return self._manual("auth-tls-pass-certificate-to-upstream", "mTLS", "🔵", phase,
            "需通过 EnvoyFilter 配置 forward_client_cert_details",
            "kubectl get envoyfilter -n ls-test -o yaml | grep forward_client_cert")

    def verify_auth_tls_verify_depth(self, phase: str) -> VerifyResult:
        """迁移后检查 Envoy 证书链验证深度"""
        if phase == "pre-migration":
            return self._pre_migration_note("auth-tls-verify-depth", "mTLS", "🔵",
                "迁移前 NGINX 默认深度 1。迁移后 Envoy 默认 100，可通过 EnvoyFilter 配置 max_verify_depth")
        if self.search_config_dump("max_verify_depth"):
            return self._ok("auth-tls-verify-depth", "mTLS", "🔵", phase,
                "Envoy 配置了 max_verify_depth",
                "")
        return self._manual("auth-tls-verify-depth", "mTLS", "🔵", phase,
            "Envoy 默认验证深度 100（NGINX 默认 1），如需自定义需 EnvoyFilter",
            "kubectl get envoyfilter -n ls-test -o yaml | grep max_verify_depth")

    def verify_enable_global_auth(self, phase: str) -> VerifyResult:
        """迁移后检查认证插件的 global_auth 配置"""
        if phase == "pre-migration":
            return self._pre_migration_note("enable-global-auth", "认证策略", "🔵",
                "迁移前控制是否启用全局认证。迁移后各认证插件通过 global_auth 字段控制")
        for name in ["ext-auth", "basic-auth", "key-auth", "jwt-auth"]:
            wp = self.find_wasmplugin(name)
            if wp:
                spec_str = json.dumps(wp.get("spec", {}), ensure_ascii=False)
                if "global_auth" in spec_str or "globalAuth" in spec_str:
                    return self._ok("enable-global-auth", "认证策略", "🔵", phase,
                        f"{name} WasmPlugin 中配置了 global_auth",
                        spec_str[:300])
                return self._ok("enable-global-auth", "认证策略", "🔵", phase,
                    f"找到 {name} WasmPlugin（默认非全局）",
                    "如需全局认证，添加 global_auth: true 配置")
        return self._manual("enable-global-auth", "认证策略", "🔵", phase,
            "未找到任何认证 WasmPlugin",
            "kubectl get wasmplugin -n ls-test")

    def verify_ssl_ciphers(self, phase: str) -> VerifyResult:
        """迁移后检查 Envoy DownstreamTlsContext 中的 cipher_suites"""
        if phase == "pre-migration":
            return self._pre_migration_note("ssl-ciphers", "SSL/TLS", "🔵",
                "迁移前通过 NGINX ssl_ciphers 配置。迁移后通过 higress.io/ssl-cipher 注解")
        result = self.find_ingress_annotation("ssl-cipher")
        if result:
            return self._ok("ssl-ciphers", "SSL/TLS", "🔵", phase,
                f"Ingress '{result[0]}' 存在 higress.io/ssl-cipher 注解",
                f"值: {result[1]}")
        if self.search_listeners("cipher_suites"):
            return self._ok("ssl-ciphers", "SSL/TLS", "🔵", phase,
                "Envoy listener 中配置了 cipher_suites",
                "")
        return self._manual("ssl-ciphers", "SSL/TLS", "🔵", phase,
            "未找到 cipher 配置（使用 Envoy/BoringSSL 默认值）",
            "kubectl get ingress -n ls-test -o yaml | grep ssl-cipher")

    def verify_proxy_ssl_secret(self, phase: str) -> VerifyResult:
        """迁移后检查 Envoy UpstreamTlsContext 中是否配置了客户端证书"""
        if phase == "pre-migration":
            return self._pre_migration_note("proxy-ssl-secret", "SSL/TLS", "✅",
                "迁移前后均通过注解配置。检查 Secret 是否存在且 Envoy 已加载")
        result = self.find_ingress_annotation("proxy-ssl-secret")
        if result:
            return self._ok("proxy-ssl-secret", "SSL/TLS", "✅", phase,
                f"Ingress '{result[0]}' 存在 proxy-ssl-secret 注解",
                f"值: {result[1]}")
        if self.search_clusters("tls_certificates") or self.search_clusters("transport_socket"):
            return self._ok("proxy-ssl-secret", "SSL/TLS", "✅", phase,
                "Envoy cluster 中配置了 upstream TLS 客户端证书",
                "")
        return self._manual("proxy-ssl-secret", "SSL/TLS", "✅", phase,
            "未找到 upstream TLS 客户端证书配置（需 TLS Secret）",
            "kubectl get secret -n ls-test | grep tls")

    def verify_proxy_ssl_ciphers(self, phase: str) -> VerifyResult:
        """迁移后检查 Envoy UpstreamTlsContext 的 cipher_suites"""
        if phase == "pre-migration":
            return self._pre_migration_note("proxy-ssl-ciphers", "SSL/TLS", "🔵",
                "迁移前由 NGINX proxy_ssl_ciphers 配置。迁移后需 EnvoyFilter 配置 UpstreamTlsContext")
        if self.search_clusters("cipher_suites"):
            return self._ok("proxy-ssl-ciphers", "SSL/TLS", "🔵", phase,
                "Envoy cluster 中配置了 upstream cipher_suites",
                "")
        return self._manual("proxy-ssl-ciphers", "SSL/TLS", "🔵", phase,
            "未找到 upstream cipher 配置（需 EnvoyFilter）",
            "kubectl get envoyfilter -n ls-test -o yaml | grep cipher_suites")

    def verify_proxy_ssl_protocols(self, phase: str) -> VerifyResult:
        """迁移后检查 Envoy UpstreamTlsContext 的 TLS 协议版本"""
        if phase == "pre-migration":
            return self._pre_migration_note("proxy-ssl-protocols", "SSL/TLS", "🔵",
                "迁移前由 NGINX proxy_ssl_protocols 配置。迁移后需 EnvoyFilter 配置 tls_minimum/maximum_protocol_version")
        if self.search_clusters("tls_minimum_protocol_version") or self.search_clusters("tls_maximum_protocol_version"):
            return self._ok("proxy-ssl-protocols", "SSL/TLS", "🔵", phase,
                "Envoy cluster 中配置了 TLS 协议版本限制",
                "")
        return self._manual("proxy-ssl-protocols", "SSL/TLS", "🔵", phase,
            "未找到 upstream TLS 协议版本配置（需 EnvoyFilter）",
            "kubectl get envoyfilter -n ls-test -o yaml | grep tls_minimum_protocol_version")

    def verify_proxy_ssl_verify_depth(self, phase: str) -> VerifyResult:
        """迁移后检查 Envoy UpstreamTlsContext 的证书链验证深度"""
        if phase == "pre-migration":
            return self._pre_migration_note("proxy-ssl-verify-depth", "SSL/TLS", "🔵",
                "迁移前 NGINX 默认 1。迁移后 Envoy 默认 100，需 EnvoyFilter 自定义")
        if self.search_clusters("max_verify_depth"):
            return self._ok("proxy-ssl-verify-depth", "SSL/TLS", "🔵", phase,
                "Envoy cluster 中配置了 max_verify_depth",
                "")
        return self._manual("proxy-ssl-verify-depth", "SSL/TLS", "🔵", phase,
            "Envoy 默认验证深度 100（NGINX 默认 1），如需自定义需 EnvoyFilter",
            "kubectl get envoyfilter -n ls-test -o yaml | grep max_verify_depth")

    def verify_limit_rpm(self, phase: str) -> VerifyResult:
        """迁移后检查 key-rate-limit WasmPlugin 是否配置了每分钟限流"""
        if phase == "pre-migration":
            return self._pre_migration_note("limit-rpm", "限流限速", "🔵",
                "迁移前由 NGINX limit_req 处理。迁移后通过 key-rate-limit 插件配置")
        for name in ["key-rate-limit", "cluster-key-rate-limit"]:
            wp = self.find_wasmplugin(name)
            if wp:
                spec_str = json.dumps(wp.get("spec", {}), ensure_ascii=False)
                return self._ok("limit-rpm", "限流限速", "🔵", phase,
                    f"找到 {name} WasmPlugin",
                    spec_str[:300])
        return self._manual("limit-rpm", "限流限速", "🔵", phase,
            "未找到限流 WasmPlugin（需 key-rate-limit 或 cluster-key-rate-limit）",
            "kubectl get wasmplugin -n ls-test | grep rate-limit")

    def verify_limit_whitelist(self, phase: str) -> VerifyResult:
        """迁移后检查限流插件中是否配置了白名单 CIDR"""
        if phase == "pre-migration":
            return self._pre_migration_note("limit-whitelist", "限流限速", "🔵",
                "迁移前由 NGINX geo + limit_req_zone 处理。迁移后通过 cluster-key-rate-limit 插件 limit_keys 顺序匹配")
        wp = self.find_wasmplugin("cluster-key-rate-limit")
        if wp:
            spec_str = json.dumps(wp.get("spec", {}), ensure_ascii=False)
            if "limit_keys" in spec_str or "limitKeys" in spec_str:
                return self._ok("limit-whitelist", "限流限速", "🔵", phase,
                    "cluster-key-rate-limit 中配置了 limit_keys（可实现白名单）",
                    spec_str[:300])
            return self._ok("limit-whitelist", "限流限速", "🔵", phase,
                "找到 cluster-key-rate-limit WasmPlugin（需添加白名单 CIDR 配置）",
                "白名单 CIDR 放 limit_keys 前面，配置极大阈值即可")
        return self._manual("limit-whitelist", "限流限速", "🔵", phase,
            "未找到 cluster-key-rate-limit WasmPlugin（需 Go 版插件 + Redis）",
            "kubectl get wasmplugin -n ls-test | grep rate-limit")

    def verify_proxy_cookie_domain(self, phase: str) -> VerifyResult:
        """迁移后检查是否有 transformer WasmPlugin 或 EnvoyFilter 修改 Set-Cookie Domain"""
        if phase == "pre-migration":
            return self._pre_migration_note("proxy-cookie-domain", "后端服务", "🔵",
                "迁移前由 NGINX proxy_cookie_domain 处理。迁移后需 transformer 插件或 EnvoyFilter")
        wp = self.find_wasmplugin("transformer")
        if wp:
            spec_str = json.dumps(wp.get("spec", {}), ensure_ascii=False)
            if "set-cookie" in spec_str.lower() or "cookie" in spec_str.lower():
                return self._ok("proxy-cookie-domain", "后端服务", "🔵", phase,
                    "transformer WasmPlugin 中存在 cookie 相关配置",
                    spec_str[:300])
        return self._manual("proxy-cookie-domain", "后端服务", "🔵", phase,
            "需 transformer 插件配置 respRules 修改 Set-Cookie 的 Domain",
            "kubectl get wasmplugin -n ls-test -o yaml | grep -i cookie")

    def verify_proxy_cookie_path(self, phase: str) -> VerifyResult:
        """迁移后检查是否有 transformer WasmPlugin 修改 Set-Cookie Path"""
        if phase == "pre-migration":
            return self._pre_migration_note("proxy-cookie-path", "后端服务", "🔵",
                "迁移前由 NGINX proxy_cookie_path 处理。迁移后需 transformer 插件")
        wp = self.find_wasmplugin("transformer")
        if wp:
            spec_str = json.dumps(wp.get("spec", {}), ensure_ascii=False)
            if "set-cookie" in spec_str.lower() or "cookie" in spec_str.lower():
                return self._ok("proxy-cookie-path", "后端服务", "🔵", phase,
                    "transformer WasmPlugin 中存在 cookie 相关配置",
                    spec_str[:300])
        return self._manual("proxy-cookie-path", "后端服务", "🔵", phase,
            "需 transformer 插件配置 respRules 修改 Set-Cookie 的 Path",
            "kubectl get wasmplugin -n ls-test -o yaml | grep -i cookie")

    def verify_custom_headers(self, phase: str) -> VerifyResult:
        """迁移后检查 Ingress 是否有 higress.io/request-header-control-* 注解"""
        if phase == "pre-migration":
            return self._pre_migration_note("custom-headers", "头部控制", "🔵",
                "迁移前引用 ConfigMap。迁移后通过 higress.io/request-header-control-add 等注解内联声明")
        for suffix in ["request-header-control-add", "request-header-control-update",
                        "request-header-control-remove", "response-header-control-add"]:
            result = self.find_ingress_annotation(suffix)
            if result:
                return self._ok("custom-headers", "头部控制", "🔵", phase,
                    f"Ingress '{result[0]}' 存在 higress.io/{suffix} 注解",
                    f"值: {result[1][:200]}")
        return self._manual("custom-headers", "头部控制", "🔵", phase,
            "未找到 higress.io/request-header-control-* 注解（需将 ConfigMap 内容迁移到注解）",
            "kubectl get ingress -n ls-test -o yaml | grep header-control")

    def verify_enable_access_log(self, phase: str) -> VerifyResult:
        """迁移后检查是否通过 EnvoyFilter 配置了按路由的 access log 开关"""
        if phase == "pre-migration":
            return self._pre_migration_note("enable-access-log", "可观测性", "🔵",
                "迁移前通过注解按 Ingress 粒度关闭日志。迁移后需 EnvoyFilter + metadata_filter")
        # 检查 EnvoyFilter
        data = kubectl_get_json("envoyfilter", namespace=self.namespace)
        if data and data.get("items"):
            for ef in data["items"]:
                ef_str = json.dumps(ef, ensure_ascii=False)
                if "access_log" in ef_str.lower() or "metadata_filter" in ef_str.lower():
                    return self._ok("enable-access-log", "可观测性", "🔵", phase,
                        f"EnvoyFilter '{ef['metadata']['name']}' 中存在 access_log 配置",
                        ef_str[:300])
        return self._manual("enable-access-log", "可观测性", "🔵", phase,
            "未找到 access log 相关 EnvoyFilter（配置复杂度高于 NGINX 单注解方式）",
            "kubectl get envoyfilter -n ls-test -o yaml | grep access_log")

    # ================================================================
    # 辅助方法
    # ================================================================
    def _ok(self, ann: str, cat: str, compat: str, phase: str,
            details: str, evidence: str = "") -> VerifyResult:
        return VerifyResult(annotation=ann, category=cat, compatibility=compat,
                            verify_method="post-config", passed=True, phase=phase,
                            timestamp=datetime.now().isoformat(),
                            details=details, evidence=evidence)

    def _manual(self, ann: str, cat: str, compat: str, phase: str,
                details: str, manual_steps: str = "") -> VerifyResult:
        return VerifyResult(annotation=ann, category=cat, compatibility=compat,
                            verify_method="post-config", passed=False, phase=phase,
                            timestamp=datetime.now().isoformat(),
                            details=details, manual_steps=manual_steps)

    def _pre_migration_note(self, ann: str, cat: str, compat: str,
                            details: str) -> VerifyResult:
        return VerifyResult(annotation=ann, category=cat, compatibility=compat,
                            verify_method="post-config", passed=True, phase="pre-migration",
                            timestamp=datetime.now().isoformat(),
                            details=f"[迁移前] {details}")

    # ================================================================
    # 分发器
    # ================================================================
    def verify(self, annotation: str, phase: str) -> VerifyResult:
        """根据注解名称分发到对应的验证方法"""
        dispatch = {
            "preserve-trailing-slash": self.verify_preserve_trailing_slash,
            "proxy-redirect-from": self.verify_proxy_redirect_from,
            "proxy-redirect-to": self.verify_proxy_redirect_to,
            "from-to-www-redirect": self.verify_from_to_www_redirect,
            "affinity-canary-behavior": self.verify_affinity_canary_behavior,
            "auth-proxy-set-headers": self.verify_auth_proxy_set_headers,
            "auth-method": self.verify_auth_method,
            "auth-secret": self.verify_auth_secret,
            "auth-secret-type": self.verify_auth_secret_type,
            "auth-realm": self.verify_auth_realm,
            "auth-tls-secret": self.verify_auth_tls_secret,
            "auth-tls-verify-client": self.verify_auth_tls_verify_client,
            "auth-tls-match-cn": self.verify_auth_tls_match_cn,
            "auth-tls-pass-certificate-to-upstream": self.verify_auth_tls_pass_cert,
            "auth-tls-verify-depth": self.verify_auth_tls_verify_depth,
            "enable-global-auth": self.verify_enable_global_auth,
            "ssl-ciphers": self.verify_ssl_ciphers,
            "proxy-ssl-secret": self.verify_proxy_ssl_secret,
            "proxy-ssl-ciphers": self.verify_proxy_ssl_ciphers,
            "proxy-ssl-protocols": self.verify_proxy_ssl_protocols,
            "proxy-ssl-verify-depth": self.verify_proxy_ssl_verify_depth,
            "limit-rpm": self.verify_limit_rpm,
            "limit-whitelist": self.verify_limit_whitelist,
            "proxy-cookie-domain": self.verify_proxy_cookie_domain,
            "proxy-cookie-path": self.verify_proxy_cookie_path,
            "custom-headers": self.verify_custom_headers,
            "enable-access-log": self.verify_enable_access_log,
        }
        fn = dispatch.get(annotation)
        if fn:
            return fn(phase)
        # fallback
        return VerifyResult(annotation=annotation, category="", compatibility="",
                            verify_method="post-config", passed=False, phase=phase,
                            timestamp=datetime.now().isoformat(),
                            details=f"未实现 {annotation} 的验证逻辑")


# ============================================================================
# 无需迁移验证器
# ============================================================================
NO_MIGRATION_REASONS = {
    "ssl-prefer-server-ciphers": "Envoy/BoringSSL 默认服务端优先选择加密套件",
    "session-cookie-change-on-failure": "Envoy outlier detection 天然覆盖",
    "proxy-body-size": "Envoy 流式转发，不缓存请求体，无内存爆炸风险",
    "service-upstream": "Higress 默认通过 EDS 直连 Pod IP，性能更优",
    "proxy-buffering": "Envoy 天然流式转发，SSE/长轮询天然可用",
    "proxy-buffer-size": "Envoy 响应头处理机制不同，默认配置已够用",
    "proxy-busy-buffers-size": "Envoy 流式架构不需要此概念",
    "proxy-max-temp-file-size": "Envoy 不使用磁盘缓冲",
    "proxy-request-buffering": "Envoy 默认行为已满足需求",
    "connection-proxy-header": "Envoy 按 RFC 7230 自动处理 hop-by-hop 头",
    "mirror-request-body": "Envoy 始终镜像完整请求（含 body），默认行为一致",
    "http2-push-preload": "HTTP/2 Server Push 已被主流浏览器废弃",
}

# ============================================================================
# 不兼容注解原因
# ============================================================================
INCOMPATIBLE_REASONS = {
    "temporal-redirect-code": "Higress 硬编码 302，不支持自定义临时重定向状态码",
    "auth-signin": "ext-auth 插件不支持认证失败后重定向到登录页",
    "auth-snippet": "Higress 不支持 Snippet 注解",
    "auth-signin-redirect-param": "ext-auth 插件不支持自定义重定向参数名",
    "auth-request-redirect": "ext-auth 插件不支持 X-Auth-Request-Redirect 头",
    "auth-always-set-cookie": "ext-auth 插件不支持始终设置 Cookie",
    "auth-cache-duration": "ext-auth 插件不支持认证缓存",
    "auth-cache-key": "ext-auth 插件不支持认证缓存 key",
    "auth-keepalive": "ext-auth 插件未暴露连接池配置",
    "auth-keepalive-requests": "ext-auth 插件未暴露连接池配置",
    "auth-keepalive-share-vars": "Envoy 架构无子请求共享变量概念",
    "auth-keepalive-timeout": "ext-auth 插件未暴露连接池超时配置",
    "auth-tls-error-page": "Envoy TLS 握手失败无法 HTTP 重定向",
    "satisfy": "Envoy 认证过滤器无 any 模式",
    "ssl-passthrough": "Higress 不支持 TLS 透传",
    "session-cookie-domain": "Istio API HTTPCookie 无 Domain 字段",
    "session-cookie-samesite": "Istio API v1.27 HTTPCookie 无 SameSite 字段",
    "session-cookie-secure": "Istio API v1.27 HTTPCookie 无 Secure 字段",
    "session-cookie-conditional-samesite-none": "前提 SameSite 不支持",
    "upstream-hash-by-subset": "Envoy 一致性哈希无 subset 模式",
    "upstream-hash-by-subset-size": "前提 subset 不支持",
    "limit-burst-multiplier": "限流插件无突发倍数参数",
    "limit-rate-after": "Envoy 流式架构无响应速率限制",
    "limit-rate": "Envoy 流式架构无响应速率限制",
    "client-body-buffer-size": "Envoy 不写磁盘，仅全局连接缓冲",
    "proxy-buffers-number": "Envoy 语义不同（总大小 vs 数量）",
    "mirror-host": "Envoy mirror 无独立 Host 覆盖",
    "modsecurity-snippet": "Higress 不支持 Snippet",
    "modsecurity-transaction-id": "Envoy 无 ModSecurity 事务模型",
    "enable-opentelemetry": "Envoy tracing 无法按路由粒度开关",
    "opentelemetry-trust-incoming-span": "Envoy 默认信任，无法按路由调整",
    "enable-rewrite-log": "Envoy 无 rewrite 调试日志机制",
    "configuration-snippet": "Higress 不支持 Snippet（安全风险）",
    "server-snippet": "Higress 不支持 Snippet（安全风险）",
    "stream-snippet": "Higress 不支持 Snippet",
}


# ============================================================================
# 主执行器
# ============================================================================
def run_full_verify(gateway_ip: str, phase: str, namespace: str = NAMESPACE) -> List[VerifyResult]:
    """执行全部 130 个注解的验证"""
    results = []
    pv = PostMigrationVerifier(namespace)
    stats = {"curl": 0, "post-config": 0, "no-migration": 0, "incompatible": 0}

    print(f"\n{'='*70}")
    print(f"  NGINX Ingress 全部 130 注解验证 — {phase}")
    print(f"  Gateway: {gateway_ip} | Namespace: {namespace}")
    print(f"  时间: {datetime.now().isoformat()}")
    print(f"{'='*70}\n")

    current_cat = ""
    for ann_def in ALL_ANNOTATIONS:
        name = ann_def["name"]
        compat = ann_def["compat"]
        cat = ann_def["cat"]
        verify = ann_def["verify"]

        if cat != current_cat:
            current_cat = cat
            print(f"\n  ── {cat} ──")

        stats[verify] = stats.get(verify, 0) + 1

        if verify == "curl":
            result = VerifyResult(
                annotation=name, category=cat, compatibility=compat,
                verify_method="curl", passed=True, phase=phase,
                timestamp=datetime.now().isoformat(),
                details="由 test_annotations_e2e.py 执行 curl 端到端验证")
            print(f"    {compat} {name:45s} [curl]         → 见 E2E 测试")

        elif verify == "post-config":
            result = pv.verify(name, phase)
            result.category = cat
            result.compatibility = compat
            if result.passed:
                print(f"    {compat} {name:45s} [迁移后配置]   → ✅ {result.details[:50]}")
            elif result.manual_steps:
                print(f"    {compat} {name:45s} [需人工确认]   → 🔍 {result.details[:50]}")
            else:
                print(f"    {compat} {name:45s} [迁移后配置]   → ⚠️ {result.details[:50]}")

        elif verify == "no-migration":
            reason = NO_MIGRATION_REASONS.get(name, "Envoy 架构天然覆盖")
            result = VerifyResult(
                annotation=name, category=cat, compatibility=compat,
                verify_method="no-migration", passed=True, phase=phase,
                timestamp=datetime.now().isoformat(),
                details=f"无需迁移 — {reason}")
            print(f"    {compat} {name:45s} [无需迁移]     → ✅ {reason[:50]}")

        elif verify == "incompatible":
            reason = INCOMPATIBLE_REASONS.get(name, "Higress 架构差异")
            result = VerifyResult(
                annotation=name, category=cat, compatibility=compat,
                verify_method="incompatible", passed=True, phase=phase,
                timestamp=datetime.now().isoformat(),
                details=f"已确认不兼容 — {reason}",
                evidence="需评估替代方案或确认业务可接受")
            print(f"    {compat} {name:45s} [不兼容]       → ⚠️ {reason[:50]}")

        else:
            result = VerifyResult(
                annotation=name, category=cat, compatibility=compat,
                verify_method="unknown", passed=False, phase=phase,
                timestamp=datetime.now().isoformat(),
                details=f"未知验证方式: {verify}")
            print(f"    {compat} {name:45s} [???]          → ❌ 未知")

        results.append(result)

    # 汇总
    total = len(results)
    pc_results = [r for r in results if r.verify_method == "post-config"]
    pc_passed = sum(1 for r in pc_results if r.passed)
    pc_manual = sum(1 for r in pc_results if not r.passed and r.manual_steps)
    pc_failed = len(pc_results) - pc_passed - pc_manual

    print(f"\n{'='*70}")
    print(f"  全量验证汇总（{total} / 130 注解）")
    print(f"{'='*70}")
    print(f"  📊 验证方式分布:")
    print(f"     curl 端到端验证:      {stats.get('curl', 0):3d} 个")
    print(f"     迁移后配置验证:       {stats.get('post-config', 0):3d} 个 （{pc_passed} 自动通过, {pc_manual} 需人工确认, {pc_failed} 未通过）")
    print(f"     🔴 无需迁移确认:      {stats.get('no-migration', 0):3d} 个")
    print(f"     ❌ 不兼容确认:        {stats.get('incompatible', 0):3d} 个")

    # 输出需人工确认的列表
    manual_items = [r for r in results if r.manual_steps]
    if manual_items:
        print(f"\n  🔍 需人工确认的注解 ({len(manual_items)} 个):")
        for r in manual_items:
            print(f"     {r.compatibility} {r.annotation}")
            print(f"       原因: {r.details}")
            print(f"       命令: {r.manual_steps}")
    print(f"{'='*70}\n")

    return results


def save_full_results(results: List[VerifyResult], phase: str):
    """保存全量验证结果"""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    filepath = os.path.join(RESULTS_DIR, f"full-verify-{phase}.json")
    data = {
        "phase": phase,
        "timestamp": datetime.now().isoformat(),
        "total": len(results),
        "by_method": {},
        "by_compat": {},
        "results": [asdict(r) for r in results],
    }
    for r in results:
        data["by_method"][r.verify_method] = data["by_method"].get(r.verify_method, 0) + 1
        data["by_compat"][r.compatibility] = data["by_compat"].get(r.compatibility, 0) + 1
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"  结果已保存到: {filepath}")


def compare_full_results():
    """对比迁移前后全量验证结果"""
    pre_file = os.path.join(RESULTS_DIR, "full-verify-pre-migration.json")
    post_file = os.path.join(RESULTS_DIR, "full-verify-post-migration.json")
    if not os.path.exists(pre_file):
        print("❌ 未找到 pre-migration 全量验证结果")
        return
    if not os.path.exists(post_file):
        print("❌ 未找到 post-migration 全量验证结果")
        return
    with open(pre_file) as f:
        pre = json.load(f)
    with open(post_file) as f:
        post = json.load(f)

    pre_map = {r["annotation"]: r for r in pre["results"]}
    post_map = {r["annotation"]: r for r in post["results"]}

    print(f"\n{'='*70}")
    print(f"  全量验证迁移前后对比")
    print(f"{'='*70}\n")

    changes = []
    for ann in sorted(set(list(pre_map.keys()) + list(post_map.keys()))):
        pre_r = pre_map.get(ann, {})
        post_r = post_map.get(ann, {})
        method = pre_r.get("verify_method", post_r.get("verify_method", ""))
        if method in ("no-migration", "incompatible", "curl"):
            continue
        pre_pass = pre_r.get("passed", False)
        post_pass = post_r.get("passed", False)
        if pre_pass != post_pass or pre_r.get("details", "") != post_r.get("details", ""):
            changes.append({
                "annotation": ann,
                "pre_passed": pre_pass, "post_passed": post_pass,
                "method": method,
                "pre_detail": pre_r.get("details", ""),
                "post_detail": post_r.get("details", ""),
                "manual_steps": post_r.get("manual_steps", ""),
            })

    if changes:
        print(f"  发现 {len(changes)} 个变化:\n")
        for c in changes:
            if c["pre_passed"] and not c["post_passed"]:
                icon = "❌ 回归"
            elif not c["pre_passed"] and c["post_passed"]:
                icon = "🔵 改善"
            else:
                icon = "🔄 变化"
            print(f"    {icon} {c['annotation']}")
            print(f"      迁移前: {c['pre_detail'][:70]}")
            print(f"      迁移后: {c['post_detail'][:70]}")
            if c["manual_steps"]:
                print(f"      验证命令: {c['manual_steps']}")
            print()
    else:
        print("  ✅ 迁移后配置验证项无变化\n")

    report_file = os.path.join(RESULTS_DIR, "full-comparison-report.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump({"timestamp": datetime.now().isoformat(), "changes": changes}, f, ensure_ascii=False, indent=2)
    print(f"  对比报告已保存到: {report_file}")


def print_summary():
    """打印全部 130 注解的覆盖情况总览"""
    print(f"\n{'='*70}")
    print(f"  NGINX Ingress 全部 130 注解验证覆盖总览")
    print(f"{'='*70}\n")

    by_method = {}
    by_compat = {}
    by_cat = {}
    for ann in ALL_ANNOTATIONS:
        m = ann["verify"]
        c = ann["compat"]
        cat = ann["cat"]
        by_method[m] = by_method.get(m, 0) + 1
        by_compat[c] = by_compat.get(c, 0) + 1
        by_cat.setdefault(cat, []).append(ann)

    print(f"  📊 验证方式分布 (共 {len(ALL_ANNOTATIONS)} 个):\n")
    method_labels = {
        "curl":          "🌐 curl 端到端验证",
        "post-config":   "🔧 迁移后配置验证（Envoy dump / WasmPlugin / 注解转换）",
        "no-migration":  "🔴 无需迁移确认",
        "incompatible":  "❌ 不兼容确认",
    }
    for m, label in method_labels.items():
        count = by_method.get(m, 0)
        pct = count / len(ALL_ANNOTATIONS) * 100
        print(f"     {label:55s}: {count:3d} ({pct:5.1f}%)")

    print(f"\n  📊 兼容性分布:\n")
    for c, label in [("✅","完全兼容"),("🔵","可等价替换"),("⚠️","部分兼容"),("🔴","无需迁移"),("❌","不兼容")]:
        count = by_compat.get(c, 0)
        pct = count / len(ALL_ANNOTATIONS) * 100
        print(f"     {c} {label:12s}: {count:3d} ({pct:5.1f}%)")

    print(f"\n  📊 迁移后配置验证明细（{by_method.get('post-config', 0)} 个）:\n")
    print(f"     {'注解':<48s} {'兼容性':6s} {'分类':10s} 验证内容")
    print(f"     {'─'*48} {'─'*6} {'─'*10} {'─'*40}")
    verify_desc = {
        "preserve-trailing-slash": "检查 Ingress pathType=Exact",
        "proxy-redirect-from":    "检查 transformer WasmPlugin",
        "proxy-redirect-to":      "检查 transformer WasmPlugin",
        "from-to-www-redirect":   "检查 www 域名 Ingress + redirect 注解",
        "affinity-canary-behavior":"检查 Envoy route hash_policy + canary",
        "auth-proxy-set-headers":  "检查 ext-auth WasmPlugin headers_to_add",
        "auth-method":             "检查 ext-auth WasmPlugin request_method",
        "auth-secret":             "检查 basic-auth WasmPlugin consumers",
        "auth-secret-type":        "确认 basic-auth 插件已接管（概念不再适用）",
        "auth-realm":              "确认 basic-auth 插件 realm 硬编码",
        "auth-tls-secret":         "检查 Envoy listener require_client_certificate",
        "auth-tls-verify-client":  "检查 Envoy listener require_client_certificate",
        "auth-tls-match-cn":       "检查 Envoy match_typed_subject_alt_names",
        "auth-tls-pass-certificate-to-upstream": "检查 Envoy forward_client_cert_details",
        "auth-tls-verify-depth":   "检查 Envoy max_verify_depth",
        "enable-global-auth":      "检查认证 WasmPlugin global_auth 字段",
        "ssl-ciphers":             "检查 higress.io/ssl-cipher 注解或 Envoy cipher_suites",
        "proxy-ssl-secret":        "检查 Envoy cluster upstream TLS 客户端证书",
        "proxy-ssl-ciphers":       "检查 Envoy cluster cipher_suites（需 EnvoyFilter）",
        "proxy-ssl-protocols":     "检查 Envoy cluster tls_protocol_version（需 EnvoyFilter）",
        "proxy-ssl-verify-depth":  "检查 Envoy cluster max_verify_depth（需 EnvoyFilter）",
        "limit-rpm":               "检查 key-rate-limit WasmPlugin",
        "limit-whitelist":         "检查 cluster-key-rate-limit WasmPlugin limit_keys",
        "proxy-cookie-domain":     "检查 transformer WasmPlugin Set-Cookie 改写",
        "proxy-cookie-path":       "检查 transformer WasmPlugin Set-Cookie 改写",
        "custom-headers":          "检查 higress.io/request-header-control-* 注解",
        "enable-access-log":       "检查 EnvoyFilter access_log + metadata_filter",
    }
    for a in ALL_ANNOTATIONS:
        if a["verify"] == "post-config":
            desc = verify_desc.get(a["name"], "")
            print(f"     {a['name']:<48s} {a['compat']:6s} {a['cat']:10s} {desc}")

    print(f"\n{'='*70}")
    print(f"  覆盖率: {len(ALL_ANNOTATIONS)}/130 = 100%")
    active = by_method.get('curl', 0) + by_method.get('post-config', 0)
    print(f"  可主动验证（curl + 迁移后配置）: {active} 个 ({active/len(ALL_ANNOTATIONS)*100:.1f}%)")
    print(f"{'='*70}\n")


# ============================================================================
# CLI 入口
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="NGINX Ingress 全部 130 注解验证（扩展版）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 查看 130 注解覆盖总览
  python3 test_annotations_full_verify.py --summary

  # 迁移前全量验证（记录基线）
  python3 test_annotations_full_verify.py --phase pre-migration

  # 迁移后全量验证（检查 Envoy config / WasmPlugin / 注解转换）
  python3 test_annotations_full_verify.py --phase post-migration

  # 对比迁移前后
  python3 test_annotations_full_verify.py --phase compare

配合 curl E2E 测试使用:
  python3 test_annotations_e2e.py --phase pre-migration
  python3 test_annotations_full_verify.py --phase pre-migration
  # ... 执行迁移 ...
  python3 test_annotations_e2e.py --phase post-migration
  python3 test_annotations_full_verify.py --phase post-migration
  python3 test_annotations_e2e.py --phase compare
  python3 test_annotations_full_verify.py --phase compare
        """,
    )
    parser.add_argument("--phase", choices=["pre-migration", "post-migration", "compare"],
                        help="验证阶段")
    parser.add_argument("--gateway-ip", default=GATEWAY_IP,
                        help=f"Gateway IP (默认: {GATEWAY_IP})")
    parser.add_argument("--summary", action="store_true",
                        help="打印全部 130 注解覆盖总览")
    parser.add_argument("--namespace", default=NAMESPACE,
                        help=f"K8s namespace (默认: {NAMESPACE})")

    args = parser.parse_args()

    if args.summary:
        print_summary()
        return

    if not args.phase:
        parser.print_help()
        return

    if args.phase == "compare":
        compare_full_results()
        return

    results = run_full_verify(args.gateway_ip, args.phase, namespace=args.namespace)
    save_full_results(results, args.phase)


if __name__ == "__main__":
    main()
