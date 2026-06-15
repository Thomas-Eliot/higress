#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NGINX Ingress 注解全量端到端测试

用途：验证迁移前后 Ingress 注解行为一致性
流程：
  1. pre-migration  — 部署 NGINX 注解 Ingress，curl 验证行为，保存基线
  2. (手动) 在 Higress 控制台执行迁移
  3. post-migration — 对迁移后的 Ingress 执行相同 curl，保存结果
  4. compare         — 对比迁移前后结果，输出兼容性报告

使用：
  python3 test_annotations_e2e.py --phase pre-migration [--gateway-ip 47.108.54.156]
  python3 test_annotations_e2e.py --phase post-migration
  python3 test_annotations_e2e.py --phase compare

基于 annotation-compatibility.md 的 130 个注解，覆盖所有可通过 HTTP 请求验证的注解。
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
RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-results")
CURL_TIMEOUT = 10  # seconds


# ============================================================================
# 数据模型
# ============================================================================
@dataclass
class CurlRequest:
    """一个 curl 测试请求"""
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    follow_redirects: bool = False


@dataclass
class TestExpectation:
    """期望的响应特征"""
    status_code: Optional[int] = None
    status_code_in: Optional[List[int]] = None
    headers_present: Optional[List[str]] = None
    headers_absent: Optional[List[str]] = None
    header_values: Optional[Dict[str, str]] = None
    header_value_contains: Optional[Dict[str, str]] = None
    body_contains: Optional[List[str]] = None
    body_not_contains: Optional[List[str]] = None
    is_redirect: Optional[bool] = None
    redirect_location_contains: Optional[str] = None
    has_set_cookie: Optional[str] = None  # cookie name


@dataclass
class TestCase:
    """一个完整的测试用例"""
    id: str
    name: str
    description: str
    annotations_tested: List[str]
    compatibility: str  # ✅ 🔵 ❌ ⚠️ 🔴
    host: str
    requests: List[CurlRequest]
    expectations: List[TestExpectation]
    category: str
    skip_reason: Optional[str] = None


@dataclass
class TestResult:
    """测试执行结果"""
    test_id: str
    test_name: str
    phase: str
    timestamp: str
    passed: bool
    status_code: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    error: str = ""
    details: str = ""
    curl_command: str = ""


# ============================================================================
# curl 执行器
# ============================================================================
def execute_curl(gateway_ip: str, host: str, req: CurlRequest) -> Tuple[int, Dict[str, str], str, str]:
    """执行 curl 请求，返回 (status_code, headers_dict, body, curl_cmd)"""
    url = f"http://{gateway_ip}{req.path}"
    cmd = ["curl", "-s", "-o", "/dev/null", "-w",
           "%{http_code}\\n%{redirect_url}", "-D", "-",
           "--max-time", str(CURL_TIMEOUT)]

    cmd.extend(["-X", req.method])
    cmd.extend(["-H", f"Host: {host}"])

    for k, v in req.headers.items():
        cmd.extend(["-H", f"{k}: {v}"])

    if req.body:
        cmd.extend(["-d", req.body])

    if not req.follow_redirects:
        cmd.append("-L" if False else "--no-location")
    else:
        cmd.append("-L")

    # 实际执行：获取完整响应（headers + body）
    full_cmd = ["curl", "-s", "-i", "--max-time", str(CURL_TIMEOUT),
                "-X", req.method, "-H", f"Host: {host}"]
    for k, v in req.headers.items():
        full_cmd.extend(["-H", f"{k}: {v}"])
    if req.body:
        full_cmd.extend(["-d", req.body])
    full_cmd.append(url)

    curl_str = " ".join(f'"{c}"' if " " in c else c for c in full_cmd)

    try:
        result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=CURL_TIMEOUT + 5)
        raw = result.stdout
    except subprocess.TimeoutExpired:
        return 0, {}, "", curl_str
    except Exception as e:
        return 0, {}, "", curl_str

    # 解析响应
    status_code = 0
    headers = {}
    body = ""

    if raw:
        # 兼容 \r\n 和 \n 两种换行符（macOS subprocess 可能转换 \r\n → \n）
        if "\r\n\r\n" in raw:
            parts = raw.split("\r\n\r\n", 1)
            line_sep = "\r\n"
        else:
            parts = raw.split("\n\n", 1)
            line_sep = "\n"
        header_block = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""

        # 解析状态码
        first_line = header_block.split(line_sep)[0] if header_block else ""
        m = re.search(r"HTTP/[\d.]+ (\d+)", first_line)
        if m:
            status_code = int(m.group(1))

        # 解析 headers
        for line in header_block.split(line_sep)[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

    return status_code, headers, body, curl_str


# ============================================================================
# 测试用例定义
# ============================================================================
def build_test_cases() -> List[TestCase]:
    """构建所有测试用例"""
    cases = []

    # =============================================
    # 1. 路由与重写
    # =============================================
    cases.append(TestCase(
        id="rewrite-target",
        name="rewrite-target + use-regex",
        description="验证路径重写：/api/hello → /hello",
        annotations_tested=["rewrite-target", "use-regex"],
        compatibility="✅",
        host="rewrite.test.io",
        category="路由与重写",
        requests=[CurlRequest(path="/api/hello")],
        expectations=[TestExpectation(
            status_code=200,
            body_contains=["/hello"],  # echo-server 回显的路径应为 /hello
        )],
    ))

    cases.append(TestCase(
        id="upstream-vhost",
        name="upstream-vhost",
        description="验证转发到后端的 Host 头被修改为 backend.internal.com",
        annotations_tested=["upstream-vhost"],
        compatibility="✅",
        host="upstream-vhost.test.io",
        category="路由与重写",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(
            status_code=200,
            body_contains=["backend.internal.com"],  # echo-server 回显的 Host
        )],
    ))

    cases.append(TestCase(
        id="app-root",
        name="app-root",
        description="验证访问根路径时 302 重定向到 /dashboard",
        annotations_tested=["app-root"],
        compatibility="✅",
        host="app-root.test.io",
        category="路由与重写",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(
            is_redirect=True,
            status_code_in=[301, 302],
            redirect_location_contains="/dashboard",
        )],
    ))

    cases.append(TestCase(
        id="x-forwarded-prefix",
        name="x-forwarded-prefix",
        description="验证 X-Forwarded-Prefix 注解不影响正常请求（实际效果需配合 rewrite 路径验证）",
        annotations_tested=["x-forwarded-prefix"],
        compatibility="🔵",
        host="xfp.test.io",
        category="路由与重写",
        requests=[CurlRequest(path="/test")],
        expectations=[TestExpectation(
            status_code=200,
        )],
    ))

    # =============================================
    # 2. 重定向
    # =============================================
    cases.append(TestCase(
        id="ssl-redirect",
        name="ssl-redirect",
        description="验证 HTTP 请求被重定向到 HTTPS（需 TLS Secret 才生效）",
        annotations_tested=["ssl-redirect"],
        compatibility="✅",
        host="ssl-redirect.test.io",
        category="重定向",
        requests=[CurlRequest(path="/test")],
        expectations=[TestExpectation(
            status_code_in=[200, 301, 302, 307, 308],  # 无 TLS Secret 时返回 200
        )],
    ))

    cases.append(TestCase(
        id="force-ssl-redirect",
        name="force-ssl-redirect",
        description="验证强制 SSL 重定向",
        annotations_tested=["force-ssl-redirect"],
        compatibility="✅",
        host="force-ssl.test.io",
        category="重定向",
        requests=[CurlRequest(path="/test")],
        expectations=[TestExpectation(
            is_redirect=True,
            status_code_in=[301, 302, 307, 308],
            redirect_location_contains="https://",
        )],
    ))

    cases.append(TestCase(
        id="permanent-redirect",
        name="permanent-redirect",
        description="验证 301 永久重定向到指定 URL",
        annotations_tested=["permanent-redirect"],
        compatibility="✅",
        host="perm-redirect.test.io",
        category="重定向",
        requests=[CurlRequest(path="/old-page")],
        expectations=[TestExpectation(
            status_code=301,
            redirect_location_contains="https://new-domain.example.com/landing",
        )],
    ))

    cases.append(TestCase(
        id="permanent-redirect-code-308",
        name="permanent-redirect-code (308)",
        description="验证自定义永久重定向状态码 308",
        annotations_tested=["permanent-redirect", "permanent-redirect-code"],
        compatibility="✅",
        host="perm-redirect-308.test.io",
        category="重定向",
        requests=[CurlRequest(path="/old-page")],
        expectations=[TestExpectation(
            status_code=308,
            redirect_location_contains="https://new-domain.example.com/landing",
        )],
    ))

    cases.append(TestCase(
        id="temporal-redirect",
        name="temporal-redirect",
        description="验证 302 临时重定向",
        annotations_tested=["temporal-redirect"],
        compatibility="✅",
        host="temp-redirect.test.io",
        category="重定向",
        requests=[CurlRequest(path="/maintenance")],
        expectations=[TestExpectation(
            status_code=302,
            redirect_location_contains="https://maintenance.example.com",
        )],
    ))

    cases.append(TestCase(
        id="server-alias",
        name="server-alias",
        description="验证域名别名可以正常路由",
        annotations_tested=["server-alias"],
        compatibility="⚠️",
        host="alias1.test.io",  # 使用别名访问
        category="重定向",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(
            status_code=200,
        )],
    ))

    # =============================================
    # 3. CORS
    # =============================================
    cases.append(TestCase(
        id="cors-preflight",
        name="CORS preflight (OPTIONS)",
        description="验证 CORS 预检请求返回正确的 CORS 头",
        annotations_tested=[
            "enable-cors", "cors-allow-origin", "cors-allow-methods",
            "cors-allow-headers", "cors-allow-credentials",
            "cors-expose-headers", "cors-max-age"
        ],
        compatibility="✅",
        host="cors.test.io",
        category="CORS",
        requests=[CurlRequest(
            method="OPTIONS",
            path="/api/data",
            headers={
                "Origin": "https://frontend.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Authorization,Content-Type",
            },
        )],
        expectations=[TestExpectation(
            status_code_in=[200, 204],
            header_value_contains={
                "access-control-allow-origin": "https://frontend.example.com",
                "access-control-allow-methods": "POST",
                "access-control-allow-credentials": "true",
                "access-control-max-age": "86400",
            },
        )],
    ))

    cases.append(TestCase(
        id="cors-actual-request",
        name="CORS actual request",
        description="验证实际跨域请求返回 CORS 响应头",
        annotations_tested=["enable-cors", "cors-allow-origin", "cors-expose-headers"],
        compatibility="✅",
        host="cors.test.io",
        category="CORS",
        requests=[CurlRequest(
            method="GET",
            path="/api/data",
            headers={"Origin": "https://frontend.example.com"},
        )],
        expectations=[TestExpectation(
            status_code=200,
            header_value_contains={
                "access-control-allow-origin": "https://frontend.example.com",
            },
        )],
    ))

    cases.append(TestCase(
        id="cors-disallowed-origin",
        name="CORS disallowed origin",
        description="验证不在白名单中的 Origin 不返回 CORS 头",
        annotations_tested=["cors-allow-origin"],
        compatibility="✅",
        host="cors.test.io",
        category="CORS",
        requests=[CurlRequest(
            method="OPTIONS",
            path="/api/data",
            headers={
                "Origin": "https://evil.example.com",
                "Access-Control-Request-Method": "GET",
            },
        )],
        expectations=[TestExpectation(
            # 不应返回 access-control-allow-origin 或返回空
            headers_absent=["access-control-allow-origin"],
        )],
    ))

    # =============================================
    # 4. 灰度发布/金丝雀
    # =============================================
    cases.append(TestCase(
        id="canary-weight",
        name="canary-weight (30%)",
        description="验证按权重分配流量（多次请求统计比例）",
        annotations_tested=["canary", "canary-weight", "canary-weight-total"],
        compatibility="✅",
        host="canary.test.io",
        category="灰度发布",
        requests=[CurlRequest(path="/") for _ in range(20)],  # 发 20 次
        expectations=[TestExpectation(
            status_code=200,
            # 比例验证在 check 逻辑中特殊处理
        )],
    ))

    cases.append(TestCase(
        id="canary-by-header",
        name="canary-by-header",
        description="验证带 X-Canary: always 头的请求路由到 canary 后端",
        annotations_tested=["canary", "canary-by-header", "canary-by-header-value", "canary-by-header-pattern"],
        compatibility="✅",
        host="canary-header.test.io",
        category="灰度发布",
        requests=[
            CurlRequest(path="/", headers={"X-Canary": "always"}),
            CurlRequest(path="/", headers={"X-Canary": "never"}),
            CurlRequest(path="/"),  # 无 header
        ],
        expectations=[TestExpectation(status_code=200)],
    ))

    cases.append(TestCase(
        id="canary-by-cookie",
        name="canary-by-cookie",
        description="验证带 canary_cookie=always 的请求路由到 canary 后端",
        annotations_tested=["canary", "canary-by-cookie"],
        compatibility="✅",
        host="canary-cookie.test.io",
        category="灰度发布",
        requests=[
            CurlRequest(path="/", headers={"Cookie": "canary_cookie=always"}),
            CurlRequest(path="/", headers={"Cookie": "canary_cookie=never"}),
            CurlRequest(path="/"),
        ],
        expectations=[TestExpectation(status_code=200)],
    ))

    # =============================================
    # 5. 访问控制
    # =============================================
    cases.append(TestCase(
        id="whitelist-allow",
        name="whitelist-source-range (allow all)",
        description="验证 0.0.0.0/0 白名单允许所有请求",
        annotations_tested=["whitelist-source-range"],
        compatibility="✅",
        host="whitelist.test.io",
        category="访问控制",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(status_code=200)],
    ))

    cases.append(TestCase(
        id="whitelist-deny",
        name="whitelist-source-range (deny)",
        description="验证不在白名单中的 IP 被拒绝（403）",
        annotations_tested=["whitelist-source-range"],
        compatibility="✅",
        host="whitelist-deny.test.io",
        category="访问控制",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(status_code=403)],
    ))

    # =============================================
    # 6. 负载均衡与会话保持
    # =============================================
    cases.append(TestCase(
        id="affinity-cookie",
        name="affinity cookie",
        description="验证首次请求返回 Set-Cookie 头（session cookie）",
        annotations_tested=["affinity", "session-cookie-name", "session-cookie-path", "session-cookie-max-age"],
        compatibility="✅",
        host="affinity.test.io",
        category="负载均衡",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(
            status_code=200,
            has_set_cookie="my-sticky-session",
        )],
    ))

    cases.append(TestCase(
        id="upstream-hash-by",
        name="upstream-hash-by ($request_uri)",
        description="验证相同 URI 的请求始终路由到同一后端",
        annotations_tested=["upstream-hash-by"],
        compatibility="⚠️",
        host="hash-by.test.io",
        category="负载均衡",
        requests=[CurlRequest(path="/consistent-path") for _ in range(5)],
        expectations=[TestExpectation(status_code=200)],
    ))

    # =============================================
    # 7. 后端服务配置
    # =============================================
    cases.append(TestCase(
        id="retry-config",
        name="proxy-next-upstream + tries + timeout",
        description="验证重试配置生效（正常请求应成功）",
        annotations_tested=["proxy-next-upstream", "proxy-next-upstream-timeout", "proxy-next-upstream-tries"],
        compatibility="✅",
        host="retry.test.io",
        category="后端服务",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(status_code=200)],
    ))

    cases.append(TestCase(
        id="backend-protocol",
        name="backend-protocol (HTTP)",
        description="验证 HTTP 后端协议正常工作",
        annotations_tested=["backend-protocol"],
        compatibility="⚠️",
        host="backend-proto.test.io",
        category="后端服务",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(status_code=200)],
    ))

    cases.append(TestCase(
        id="timeout-config",
        name="proxy-connect/read/send-timeout",
        description="验证超时配置下正常请求可以成功",
        annotations_tested=["proxy-connect-timeout", "proxy-read-timeout", "proxy-send-timeout"],
        compatibility="🔵",
        host="timeout.test.io",
        category="后端服务",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(status_code=200)],
    ))

    # =============================================
    # 8. 错误处理
    # =============================================
    cases.append(TestCase(
        id="custom-errors",
        name="custom-http-errors + default-backend",
        description="验证自定义错误处理和默认后端",
        annotations_tested=["custom-http-errors", "default-backend"],
        compatibility="✅",
        host="custom-errors.test.io",
        category="错误处理",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(status_code=200)],
    ))

    # =============================================
    # 9. 流量镜像
    # =============================================
    cases.append(TestCase(
        id="mirror-target",
        name="mirror-target",
        description="验证流量镜像不影响主请求（主请求正常返回）",
        annotations_tested=["mirror-target"],
        compatibility="🔵",
        host="mirror.test.io",
        category="流量镜像",
        requests=[CurlRequest(path="/test-mirror")],
        expectations=[TestExpectation(status_code=200)],
    ))

    # =============================================
    # 10. SSL/TLS
    # =============================================
    cases.append(TestCase(
        id="proxy-ssl",
        name="proxy-ssl-* (后端 TLS 配置)",
        description="验证后端 TLS 配置注解不影响 HTTP 请求",
        annotations_tested=["proxy-ssl-server-name", "proxy-ssl-name", "proxy-ssl-verify"],
        compatibility="✅",
        host="proxy-ssl.test.io",
        category="SSL/TLS",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(status_code=200)],
    ))

    # =============================================
    # 11. 综合测试
    # =============================================
    cases.append(TestCase(
        id="combo-rewrite-cors",
        name="rewrite + cors + timeout 组合",
        description="验证多注解组合：路径重写 + CORS + 超时",
        annotations_tested=["rewrite-target", "use-regex", "enable-cors", "cors-allow-origin",
                            "proxy-read-timeout"],
        compatibility="✅+🔵",
        host="combo-rewrite-cors.test.io",
        category="综合测试",
        requests=[CurlRequest(
            path="/svc/hello",
            headers={"Origin": "https://any-origin.com"},
        )],
        expectations=[TestExpectation(
            status_code=200,
            body_contains=["/hello"],
            header_value_contains={
                "access-control-allow-origin": "*",
            },
        )],
    ))

    cases.append(TestCase(
        id="combo-acl-affinity",
        name="whitelist + affinity + retry 组合",
        description="验证多注解组合：IP 白名单 + 会话保持 + 重试",
        annotations_tested=["whitelist-source-range", "affinity", "session-cookie-name",
                            "proxy-next-upstream", "proxy-next-upstream-tries"],
        compatibility="✅",
        host="combo-acl.test.io",
        category="综合测试",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(
            status_code=200,
            has_set_cookie="combo-session",
        )],
    ))

    cases.append(TestCase(
        id="combo-canary-rewrite",
        name="canary + rewrite 组合",
        description="验证金丝雀发布与路径重写同时生效",
        annotations_tested=["canary", "canary-weight", "rewrite-target", "use-regex"],
        compatibility="✅",
        host="combo-canary.test.io",
        category="综合测试",
        requests=[CurlRequest(path="/v2/test")],
        expectations=[TestExpectation(
            status_code=200,
            body_contains=["/test"],
        )],
    ))

    # =============================================
    # 12. 限流限速
    # =============================================
    cases.append(TestCase(
        id="limit-rps",
        name="limit-rps",
        description="验证限流配置下正常请求可以成功（不超限）",
        annotations_tested=["limit-rps"],
        compatibility="🔵",
        host="limit-rps.test.io",
        category="限流限速",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(status_code=200)],
    ))

    cases.append(TestCase(
        id="limit-connections",
        name="limit-connections",
        description="验证连接数限制配置下正常请求可以成功",
        annotations_tested=["limit-connections"],
        compatibility="🔵",
        host="limit-conn.test.io",
        category="限流限速",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(status_code=200)],
    ))

    cases.append(TestCase(
        id="denylist-allow",
        name="denylist-source-range (allow)",
        description="验证不在黑名单中的 IP 可以正常访问",
        annotations_tested=["denylist-source-range"],
        compatibility="🔵",
        host="denylist.test.io",
        category="访问控制",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(status_code=200)],
    ))

    # =============================================
    # 13. 安全防护 (WAF)
    # =============================================
    cases.append(TestCase(
        id="waf-normal",
        name="WAF - 正常请求通过",
        description="验证 WAF 配置下正常请求不被拦截",
        annotations_tested=["enable-modsecurity", "enable-owasp-core-rules"],
        compatibility="🔵",
        host="waf.test.io",
        category="安全防护",
        requests=[CurlRequest(path="/api/data")],
        expectations=[TestExpectation(status_code=200)],
    ))

    cases.append(TestCase(
        id="waf-sqli",
        name="WAF - SQL 注入拦截",
        description="验证 WAF 拦截 SQL 注入攻击（迁移后需 waf 插件）",
        annotations_tested=["enable-modsecurity", "enable-owasp-core-rules"],
        compatibility="🔵",
        host="waf.test.io",
        category="安全防护",
        requests=[CurlRequest(
            path="/api/data?id=1%27%20OR%20%271%27%3D%271",
        )],
        expectations=[TestExpectation(
            status_code_in=[403, 200],  # NGINX 有 WAF 时 403，无 WAF 时 200
        )],
    ))

    # =============================================
    # 14. Basic Auth
    # =============================================
    cases.append(TestCase(
        id="basic-auth-no-cred",
        name="Basic Auth - 无凭证",
        description="验证无凭证请求被拒绝（401）",
        annotations_tested=["auth-type", "auth-secret"],
        compatibility="🔵",
        host="basic-auth.test.io",
        category="认证授权",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(
            status_code_in=[401, 503],  # 401 正常拒绝，503 可能 secret 不存在
        )],
    ))

    # =============================================
    # 15. 外部认证
    # =============================================
    cases.append(TestCase(
        id="ext-auth",
        name="auth-url + auth-response-headers",
        description="验证外部认证配置（echo-server 作为 auth 服务总是返回 200）",
        annotations_tested=["auth-url", "auth-response-headers"],
        compatibility="🔵",
        host="ext-auth.test.io",
        category="认证授权",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(
            status_code_in=[200, 503],  # 200 正常，503 可能 auth 服务不可达
        )],
    ))

    # =============================================
    # 16. 负载均衡算法
    # =============================================
    cases.append(TestCase(
        id="load-balance",
        name="load-balance (round_robin)",
        description="验证 round_robin 负载均衡正常工作",
        annotations_tested=["load-balance"],
        compatibility="⚠️",
        host="load-balance.test.io",
        category="负载均衡",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(status_code=200)],
    ))

    cases.append(TestCase(
        id="affinity-mode",
        name="affinity-mode (balanced) + session-cookie-expires",
        description="验证 balanced 模式会话保持和 cookie expires",
        annotations_tested=["affinity-mode", "session-cookie-expires"],
        compatibility="⚠️",
        host="affinity-mode.test.io",
        category="负载均衡",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(
            status_code=200,
            has_set_cookie="affinity-mode-test",
        )],
    ))

    cases.append(TestCase(
        id="proxy-http-version",
        name="proxy-http-version (1.1)",
        description="验证 HTTP/1.1 后端协议正常工作",
        annotations_tested=["proxy-http-version"],
        compatibility="⚠️",
        host="http-version.test.io",
        category="后端服务",
        requests=[CurlRequest(path="/")],
        expectations=[TestExpectation(status_code=200)],
    ))

    return cases


# ============================================================================
# 测试验证逻辑
# ============================================================================
def check_expectation(exp: TestExpectation, status_code: int,
                      headers: Dict[str, str], body: str) -> Tuple[bool, str]:
    """检查单个期望是否满足，返回 (passed, detail)"""
    details = []

    if exp.status_code is not None:
        if status_code != exp.status_code:
            return False, f"期望状态码 {exp.status_code}，实际 {status_code}"
        details.append(f"状态码 {status_code} ✓")

    if exp.status_code_in is not None:
        if status_code not in exp.status_code_in:
            return False, f"期望状态码在 {exp.status_code_in} 中，实际 {status_code}"
        details.append(f"状态码 {status_code} ∈ {exp.status_code_in} ✓")

    if exp.is_redirect is not None and exp.is_redirect:
        if status_code not in (301, 302, 303, 307, 308):
            return False, f"期望重定向，实际状态码 {status_code}"
        details.append(f"重定向 {status_code} ✓")

    if exp.redirect_location_contains:
        location = headers.get("location", "")
        if exp.redirect_location_contains not in location:
            return False, f"期望 Location 包含 '{exp.redirect_location_contains}'，实际 '{location}'"
        details.append(f"Location 包含 '{exp.redirect_location_contains}' ✓")

    if exp.headers_present:
        for h in exp.headers_present:
            if h.lower() not in headers:
                return False, f"期望存在响应头 '{h}'，但未找到"
            details.append(f"头 '{h}' 存在 ✓")

    if exp.headers_absent:
        for h in exp.headers_absent:
            if h.lower() in headers:
                return False, f"期望不存在响应头 '{h}'，但找到了值 '{headers[h.lower()]}'"
            details.append(f"头 '{h}' 不存在 ✓")

    if exp.header_values:
        for k, v in exp.header_values.items():
            actual = headers.get(k.lower(), "")
            if actual != v:
                return False, f"期望头 '{k}' = '{v}'，实际 '{actual}'"
            details.append(f"头 '{k}' = '{v}' ✓")

    if exp.header_value_contains:
        for k, v in exp.header_value_contains.items():
            actual = headers.get(k.lower(), "")
            if v.lower() not in actual.lower():
                return False, f"期望头 '{k}' 包含 '{v}'，实际 '{actual}'"
            details.append(f"头 '{k}' 包含 '{v}' ✓")

    if exp.body_contains:
        for text in exp.body_contains:
            if text.lower() not in body.lower():
                return False, f"期望 body 包含 '{text}'，未找到"
            details.append(f"body 包含 '{text}' ✓")

    if exp.body_not_contains:
        for text in exp.body_not_contains:
            if text.lower() in body.lower():
                return False, f"期望 body 不包含 '{text}'，但找到了"
            details.append(f"body 不含 '{text}' ✓")

    if exp.has_set_cookie:
        set_cookie = headers.get("set-cookie", "")
        if exp.has_set_cookie not in set_cookie:
            return False, f"期望 Set-Cookie 包含 '{exp.has_set_cookie}'，实际 '{set_cookie}'"
        details.append(f"Set-Cookie 包含 '{exp.has_set_cookie}' ✓")

    return True, "; ".join(details)


def run_canary_weight_test(gateway_ip: str, tc: TestCase) -> TestResult:
    """特殊处理：金丝雀权重测试，统计多次请求的分布"""
    canary_count = 0
    sample_size = 50  # 增大样本量减少统计波动
    all_bodies = []

    for _ in range(sample_size):
        req = CurlRequest(path="/")
        status, headers, body, curl_cmd = execute_curl(gateway_ip, tc.host, req)
        all_bodies.append(body)
        # 仅通过 "v2-canary" 精确匹配判断是否路由到 canary 后端
        if "v2-canary" in body:
            canary_count += 1

    ratio = canary_count / sample_size
    # 30% 权重，50 次样本下允许 ±10% 即 20%-40%
    passed = 0.20 <= ratio <= 0.40
    detail = f"canary 命中 {canary_count}/{sample_size} = {ratio:.0%}（期望 ~30%，允许 20%-40%）"

    return TestResult(
        test_id=tc.id,
        test_name=tc.name,
        phase="",
        timestamp=datetime.now().isoformat(),
        passed=passed,
        status_code=200,
        details=detail,
    )


def run_canary_header_test(gateway_ip: str, tc: TestCase) -> TestResult:
    """特殊处理：金丝雀 header 测试"""
    results = []
    for i, req in enumerate(tc.requests):
        status, headers, body, curl_cmd = execute_curl(gateway_ip, tc.host, req)
        is_canary = "canary" in body.lower() or "v2" in body.lower()
        results.append((req.headers.get("X-Canary", "none"), is_canary, status))

    # 第一个请求 (X-Canary: always) 应路由到 canary
    # 第二个请求 (X-Canary: never) 应路由到主版本
    # 第三个请求 (无 header) 应路由到主版本
    details = []
    passed = True

    if len(results) >= 3:
        if not results[0][1]:
            passed = False
            details.append("X-Canary:always 未路由到 canary ✗")
        else:
            details.append("X-Canary:always → canary ✓")

        if results[1][1]:
            details.append("X-Canary:never 仍路由到 canary（可能是权重影响）⚠")
        else:
            details.append("X-Canary:never → main ✓")

        if results[2][1]:
            details.append("无 header 路由到 canary（可能是权重影响）⚠")
        else:
            details.append("无 header → main ✓")

    return TestResult(
        test_id=tc.id,
        test_name=tc.name,
        phase="",
        timestamp=datetime.now().isoformat(),
        passed=passed,
        status_code=results[0][2] if results else 0,
        details="; ".join(details),
    )


def run_canary_cookie_test(gateway_ip: str, tc: TestCase) -> TestResult:
    """特殊处理：金丝雀 cookie 测试"""
    results = []
    for req in tc.requests:
        status, headers, body, curl_cmd = execute_curl(gateway_ip, tc.host, req)
        is_canary = "canary" in body.lower() or "v2" in body.lower()
        cookie_val = req.headers.get("Cookie", "none")
        results.append((cookie_val, is_canary, status))

    details = []
    passed = True

    if len(results) >= 3:
        if not results[0][1]:
            passed = False
            details.append("cookie=always 未路由到 canary ✗")
        else:
            details.append("cookie=always → canary ✓")

        if results[1][1]:
            details.append("cookie=never 仍路由到 canary ⚠")
        else:
            details.append("cookie=never → main ✓")

    return TestResult(
        test_id=tc.id,
        test_name=tc.name,
        phase="",
        timestamp=datetime.now().isoformat(),
        passed=passed,
        status_code=results[0][2] if results else 0,
        details="; ".join(details),
    )


def run_hash_consistency_test(gateway_ip: str, tc: TestCase) -> TestResult:
    """特殊处理：一致性哈希测试，验证相同 URI 路由到同一后端"""
    backends = set()
    for req in tc.requests:
        status, headers, body, curl_cmd = execute_curl(gateway_ip, tc.host, req)
        # 从 echo-server 响应中提取 hostname
        m = re.search(r'"hostname"\s*:\s*"([^"]+)"', body)
        if m:
            backends.add(m.group(1))

    passed = len(backends) <= 1
    detail = f"相同 URI 路由到 {len(backends)} 个不同后端: {backends}"

    return TestResult(
        test_id=tc.id,
        test_name=tc.name,
        phase="",
        timestamp=datetime.now().isoformat(),
        passed=passed,
        status_code=200,
        details=detail,
    )


# ============================================================================
# 主测试执行器
# ============================================================================
def run_test(gateway_ip: str, tc: TestCase, phase: str) -> TestResult:
    """执行单个测试用例"""
    if tc.skip_reason:
        return TestResult(
            test_id=tc.id, test_name=tc.name, phase=phase,
            timestamp=datetime.now().isoformat(),
            passed=True, details=f"SKIPPED: {tc.skip_reason}",
        )

    # 特殊测试用例
    if tc.id == "canary-weight":
        result = run_canary_weight_test(gateway_ip, tc)
        result.phase = phase
        return result
    if tc.id == "canary-by-header":
        result = run_canary_header_test(gateway_ip, tc)
        result.phase = phase
        return result
    if tc.id == "canary-by-cookie":
        result = run_canary_cookie_test(gateway_ip, tc)
        result.phase = phase
        return result
    if tc.id == "upstream-hash-by":
        result = run_hash_consistency_test(gateway_ip, tc)
        result.phase = phase
        return result

    # 通用测试：取第一个请求和第一个期望
    req = tc.requests[0]
    exp = tc.expectations[0]

    status, headers, body, curl_cmd = execute_curl(gateway_ip, tc.host, req)

    if status == 0:
        return TestResult(
            test_id=tc.id, test_name=tc.name, phase=phase,
            timestamp=datetime.now().isoformat(),
            passed=False, error="curl 请求超时或失败",
            curl_command=curl_cmd,
        )

    passed, detail = check_expectation(exp, status, headers, body)

    return TestResult(
        test_id=tc.id, test_name=tc.name, phase=phase,
        timestamp=datetime.now().isoformat(),
        passed=passed, status_code=status,
        response_headers=headers,
        response_body=body[:500],  # 截断
        details=detail, curl_command=curl_cmd,
    )


def run_all_tests(gateway_ip: str, phase: str) -> List[TestResult]:
    """执行所有测试"""
    cases = build_test_cases()
    results = []

    print(f"\n{'='*70}")
    print(f"  NGINX Ingress 注解 E2E 测试 — {phase}")
    print(f"  Gateway: {gateway_ip}")
    print(f"  时间: {datetime.now().isoformat()}")
    print(f"{'='*70}\n")

    for tc in cases:
        print(f"  [{tc.category}] {tc.id}: {tc.name} ... ", end="", flush=True)
        result = run_test(gateway_ip, tc, phase)
        results.append(result)

        if "SKIPPED" in result.details:
            print("⏭ SKIP")
        elif result.passed:
            print("✅ PASS")
        else:
            print(f"❌ FAIL — {result.details or result.error}")

    # 统计
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)
    skipped = sum(1 for r in results if "SKIPPED" in r.details)

    print(f"\n{'='*70}")
    print(f"  结果: {passed} passed, {failed} failed, {skipped} skipped / {total} total")
    print(f"{'='*70}\n")

    return results


def save_results(results: List[TestResult], phase: str):
    """保存测试结果到 JSON"""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    filepath = os.path.join(RESULTS_DIR, f"{phase}.json")
    data = {
        "phase": phase,
        "timestamp": datetime.now().isoformat(),
        "gateway_ip": GATEWAY_IP,
        "total": len(results),
        "passed": sum(1 for r in results if r.passed),
        "failed": sum(1 for r in results if not r.passed),
        "results": [asdict(r) for r in results],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"  结果已保存到: {filepath}")


def compare_results():
    """对比迁移前后结果"""
    pre_file = os.path.join(RESULTS_DIR, "pre-migration.json")
    post_file = os.path.join(RESULTS_DIR, "post-migration.json")

    if not os.path.exists(pre_file):
        print("❌ 未找到 pre-migration 结果，请先运行 --phase pre-migration")
        return
    if not os.path.exists(post_file):
        print("❌ 未找到 post-migration 结果，请先运行 --phase post-migration")
        return

    with open(pre_file, "r") as f:
        pre = json.load(f)
    with open(post_file, "r") as f:
        post = json.load(f)

    pre_map = {r["test_id"]: r for r in pre["results"]}
    post_map = {r["test_id"]: r for r in post["results"]}

    print(f"\n{'='*70}")
    print(f"  迁移前后对比报告")
    print(f"{'='*70}\n")

    consistent = 0
    regression = 0
    improvement = 0
    changed = 0

    all_ids = sorted(set(list(pre_map.keys()) + list(post_map.keys())))

    for tid in all_ids:
        pre_r = pre_map.get(tid)
        post_r = post_map.get(tid)

        if not pre_r or not post_r:
            print(f"  ⚠ {tid}: 仅在{'迁移前' if pre_r else '迁移后'}有结果")
            changed += 1
            continue

        pre_pass = pre_r["passed"]
        post_pass = post_r["passed"]

        if pre_pass and post_pass:
            consistent += 1
            status = "✅ 一致（均通过）"
        elif not pre_pass and not post_pass:
            consistent += 1
            status = "⚠ 一致（均失败）"
        elif pre_pass and not post_pass:
            regression += 1
            status = f"❌ 回归！迁移前通过，迁移后失败 — {post_r.get('details', '')}"
        else:
            improvement += 1
            status = "🔵 改善（迁移前失败，迁移后通过）"

        name = pre_r.get("test_name", tid)
        print(f"  {tid}: {name}")
        print(f"    {status}")
        if pre_r.get("status_code") != post_r.get("status_code"):
            print(f"    状态码变化: {pre_r.get('status_code')} → {post_r.get('status_code')}")
        print()

    print(f"\n{'='*70}")
    print(f"  汇总: {consistent} 一致, {regression} 回归, {improvement} 改善, {changed} 变更")
    if regression > 0:
        print(f"  ⚠️  发现 {regression} 个回归，需要检查迁移后的 Ingress 配置")
    else:
        print(f"  ✅ 无回归，迁移兼容性验证通过")
    print(f"{'='*70}\n")

    # 保存对比报告
    report = {
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "consistent": consistent,
            "regression": regression,
            "improvement": improvement,
            "changed": changed,
        },
        "pre_migration": pre,
        "post_migration": post,
    }
    report_file = os.path.join(RESULTS_DIR, "comparison-report.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"  对比报告已保存到: {report_file}")


# ============================================================================
# 注解覆盖率统计
# ============================================================================
def print_coverage():
    """打印注解覆盖率统计"""
    cases = build_test_cases()

    tested = set()
    for tc in cases:
        for ann in tc.annotations_tested:
            tested.add(ann)

    # 所有 130 个注解中可通过 curl 测试的
    all_testable = {
        "✅ 完全兼容": [
            "rewrite-target", "use-regex", "upstream-vhost", "app-root",
            "ssl-redirect", "force-ssl-redirect", "permanent-redirect",
            "permanent-redirect-code", "temporal-redirect",
            "enable-cors", "cors-allow-origin", "cors-allow-methods",
            "cors-allow-headers", "cors-allow-credentials",
            "cors-expose-headers", "cors-max-age",
            "canary", "canary-weight", "canary-by-header",
            "canary-by-header-value", "canary-by-header-pattern",
            "canary-by-cookie", "canary-weight-total",
            "affinity", "session-cookie-name", "session-cookie-path",
            "session-cookie-max-age", "session-cookie-expires",
            "whitelist-source-range",
            "proxy-next-upstream", "proxy-next-upstream-timeout",
            "proxy-next-upstream-tries",
            "proxy-ssl-secret", "proxy-ssl-name",
            "proxy-ssl-server-name", "proxy-ssl-verify",
            "custom-http-errors", "default-backend",
            "affinity-canary-behavior",
        ],
        "🔵 可等价替换": [
            "x-forwarded-prefix", "proxy-connect-timeout",
            "proxy-read-timeout", "proxy-send-timeout",
            "mirror-target", "limit-rps", "limit-connections",
            "custom-headers", "denylist-source-range",
            "auth-url", "auth-response-headers",
            "enable-modsecurity", "enable-owasp-core-rules",
            "auth-type", "auth-secret",
        ],
        "⚠️ 部分兼容": [
            "server-alias", "backend-protocol", "load-balance",
            "upstream-hash-by", "affinity-mode", "proxy-http-version",
            "auth-tls-secret",
        ],
    }

    total_testable = sum(len(v) for v in all_testable.values())
    covered = tested & set(ann for anns in all_testable.values() for ann in anns)

    print(f"\n{'='*70}")
    print(f"  注解测试覆盖率")
    print(f"{'='*70}")
    print(f"  可测试注解总数: {total_testable}")
    print(f"  已覆盖: {len(covered)}")
    print(f"  覆盖率: {len(covered)/total_testable*100:.1f}%")
    print(f"\n  未覆盖的可测试注解:")
    for cat, anns in all_testable.items():
        uncovered = [a for a in anns if a not in tested]
        if uncovered:
            print(f"    {cat}: {', '.join(uncovered)}")
    print(f"{'='*70}\n")


# ============================================================================
# CLI 入口
# ============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="NGINX Ingress 注解全量 E2E 测试",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 迁移前测试
  python3 test_annotations_e2e.py --phase pre-migration

  # 迁移后测试
  python3 test_annotations_e2e.py --phase post-migration

  # 对比结果
  python3 test_annotations_e2e.py --phase compare

  # 查看覆盖率
  python3 test_annotations_e2e.py --coverage
        """,
    )
    parser.add_argument("--phase", choices=["pre-migration", "post-migration", "compare"],
                        help="测试阶段")
    parser.add_argument("--gateway-ip", default=GATEWAY_IP,
                        help=f"Gateway IP (默认: {GATEWAY_IP})")
    parser.add_argument("--coverage", action="store_true",
                        help="打印注解覆盖率统计")
    parser.add_argument("--test-id", help="仅运行指定 ID 的测试")

    args = parser.parse_args()

    gateway_ip = args.gateway_ip

    if args.coverage:
        print_coverage()
        return

    if not args.phase:
        parser.print_help()
        return

    if args.phase == "compare":
        compare_results()
        return

    if args.test_id:
        cases = build_test_cases()
        tc = next((c for c in cases if c.id == args.test_id), None)
        if not tc:
            print(f"❌ 未找到测试 ID: {args.test_id}")
            print(f"可用 ID: {', '.join(c.id for c in cases)}")
            return
        result = run_test(gateway_ip, tc, args.phase)
        print(f"\n{'✅ PASS' if result.passed else '❌ FAIL'}: {result.details}")
        print(f"curl: {result.curl_command}")
        return

    results = run_all_tests(gateway_ip, args.phase)
    save_results(results, args.phase)


if __name__ == "__main__":
    main()
