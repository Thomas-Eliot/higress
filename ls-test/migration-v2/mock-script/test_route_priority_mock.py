#!/usr/bin/env python3
"""Mock Ingress 验证路由优先级冲突检测。

构造场景：
1. 同 host 下 regex Ingress + prefix Ingress，路径有重叠 → 应检测到冲突
2. 同 host 下 regex Ingress + prefix Ingress，路径无重叠 → 无冲突
3. 不同 host → 无冲突
4. 同 host 多个 regex + 多个 prefix → 多个冲突
"""

import sys
import os

# ============================================================
# Part 1: 验证 v2 库的 RoutePriorityAnalyzer
# ============================================================
print("=" * 70)
print("Part 1: 验证 v2 库 RoutePriorityAnalyzer")
print("=" * 70)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from higress_migrate.analyzer.route_priority_analyzer import RoutePriorityAnalyzer
from higress_migrate.models import IngressResource


def make_ingress(name, namespace, annotations, rules):
    raw_yaml = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {"name": name, "namespace": namespace, "annotations": annotations},
        "spec": {"rules": rules},
    }
    nginx_anns = {k: v for k, v in annotations.items()
                  if k.startswith("nginx.ingress.kubernetes.io/")}
    return IngressResource(
        name=name, namespace=namespace, file_path="mock.yaml",
        annotations=nginx_anns, raw_yaml=raw_yaml,
    )


def rule(host, paths):
    """paths: [(path, pathType, svcName, svcPort)]"""
    return {
        "host": host,
        "http": {
            "paths": [
                {
                    "path": p, "pathType": pt,
                    "backend": {"service": {"name": svc, "port": {"number": int(port)}}},
                }
                for p, pt, svc, port in paths
            ]
        },
    }


analyzer = RoutePriorityAnalyzer()

# --- 场景 1: 同 host，regex + prefix，路径重叠 ---
print("\n--- 场景 1: 同 host，regex + prefix，路径重叠 ---")
ing_regex = make_ingress(
    "api-regex", "default",
    {"nginx.ingress.kubernetes.io/use-regex": "true",
     "nginx.ingress.kubernetes.io/rewrite-target": "/$2"},
    [rule("api.example.com", [
        ("/api(/|$)(.*)", "ImplementationSpecific", "api-v2-svc", "8080"),
    ])],
)
ing_prefix = make_ingress(
    "api-prefix", "default", {},
    [rule("api.example.com", [
        ("/api", "Prefix", "api-v1-svc", "80"),
    ])],
)
result = analyzer.analyze([ing_regex, ing_prefix])
print(f"  regex Ingresses: {result.regex_ingresses}")
print(f"  冲突数量: {len(result.conflicts)}")
for c in result.conflicts:
    print(f"  ⚠️  {c.description}")
assert len(result.conflicts) == 1, f"期望 1 个冲突，实际 {len(result.conflicts)}"
print("  ✅ PASS")

# --- 场景 2: 同 host，regex + prefix，路径不重叠 ---
print("\n--- 场景 2: 同 host，regex + prefix，路径不重叠 ---")
ing_regex2 = make_ingress(
    "user-regex", "default",
    {"nginx.ingress.kubernetes.io/use-regex": "true"},
    [rule("app.example.com", [
        ("/users/(\\d+)", "ImplementationSpecific", "user-svc", "80"),
    ])],
)
ing_prefix2 = make_ingress(
    "order-prefix", "default", {},
    [rule("app.example.com", [
        ("/orders", "Prefix", "order-svc", "80"),
    ])],
)
result2 = analyzer.analyze([ing_regex2, ing_prefix2])
print(f"  冲突数量: {len(result2.conflicts)}")
assert len(result2.conflicts) == 0, f"期望 0 个冲突，实际 {len(result2.conflicts)}"
print("  ✅ PASS")

# --- 场景 3: 不同 host ---
print("\n--- 场景 3: 不同 host ---")
ing_regex3 = make_ingress(
    "regex-a", "default",
    {"nginx.ingress.kubernetes.io/use-regex": "true"},
    [rule("a.example.com", [
        ("/api/(.*)", "ImplementationSpecific", "svc-a", "80"),
    ])],
)
ing_prefix3 = make_ingress(
    "prefix-b", "default", {},
    [rule("b.example.com", [
        ("/api", "Prefix", "svc-b", "80"),
    ])],
)
result3 = analyzer.analyze([ing_regex3, ing_prefix3])
print(f"  冲突数量: {len(result3.conflicts)}")
assert len(result3.conflicts) == 0, f"期望 0 个冲突，实际 {len(result3.conflicts)}"
print("  ✅ PASS")

# --- 场景 4: 多个 regex + 多个 prefix，同 host ---
print("\n--- 场景 4: 多个 regex + 多个 prefix，同 host ---")
ing_multi_regex = make_ingress(
    "multi-regex", "default",
    {"nginx.ingress.kubernetes.io/use-regex": "true"},
    [rule("shop.example.com", [
        ("/product/(\\d+)", "ImplementationSpecific", "product-detail-svc", "80"),
        ("/cart/(.*)", "ImplementationSpecific", "cart-svc", "80"),
    ])],
)
ing_multi_prefix = make_ingress(
    "multi-prefix", "default", {},
    [rule("shop.example.com", [
        ("/product", "Prefix", "product-list-svc", "80"),
        ("/cart", "Prefix", "cart-legacy-svc", "80"),
    ])],
)
result4 = analyzer.analyze([ing_multi_regex, ing_multi_prefix])
print(f"  冲突数量: {len(result4.conflicts)}")
for c in result4.conflicts:
    print(f"  ⚠️  {c.description}")
assert len(result4.conflicts) == 2, f"期望 2 个冲突，实际 {len(result4.conflicts)}"
print("  ✅ PASS")

# --- 场景 5: 模拟真实场景 - wildcard host ---
print("\n--- 场景 5: wildcard host * 下 regex + prefix ---")
ing_wildcard_regex = make_ingress(
    "wildcard-regex", "default",
    {"nginx.ingress.kubernetes.io/use-regex": "true"},
    [rule("*", [
        ("/api/v1/(.*)", "ImplementationSpecific", "api-new-svc", "8080"),
    ])],
)
ing_wildcard_prefix = make_ingress(
    "wildcard-prefix", "default", {},
    [rule("*", [
        ("/api/v1", "Prefix", "api-old-svc", "80"),
    ])],
)
result5 = analyzer.analyze([ing_wildcard_regex, ing_wildcard_prefix])
print(f"  冲突数量: {len(result5.conflicts)}")
for c in result5.conflicts:
    print(f"  ⚠️  {c.description}")
assert len(result5.conflicts) == 1, f"期望 1 个冲突，实际 {len(result5.conflicts)}"
print("  ✅ PASS")


# ============================================================
# Part 2: 验证 standalone 分析器的 analyze_route_priority
# ============================================================
print("\n" + "=" * 70)
print("Part 2: 验证 standalone 分析器 analyze_route_priority")
print("=" * 70)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from nginx_ingress_migration_analyzer import MigrationAnalyzer

sa = MigrationAnalyzer.__new__(MigrationAnalyzer)

# 构造 standalone 格式的 ingress 列表: [(ns_name, ing_dict)]
mock_ingresses = [
    ("default", {
        "metadata": {
            "name": "api-regex",
            "annotations": {
                "nginx.ingress.kubernetes.io/use-regex": "true",
                "nginx.ingress.kubernetes.io/rewrite-target": "/$2",
            },
        },
        "spec": {
            "rules": [{
                "host": "api.example.com",
                "http": {
                    "paths": [{
                        "path": "/api(/|$)(.*)",
                        "pathType": "ImplementationSpecific",
                        "backend": {"service": {"name": "api-v2-svc", "port": {"number": 8080}}},
                    }]
                },
            }]
        },
    }),
    ("default", {
        "metadata": {
            "name": "api-prefix",
            "annotations": {},
        },
        "spec": {
            "rules": [{
                "host": "api.example.com",
                "http": {
                    "paths": [{
                        "path": "/api",
                        "pathType": "Prefix",
                        "backend": {"service": {"name": "api-v1-svc", "port": {"number": 80}}},
                    }]
                },
            }]
        },
    }),
]

conflicts = sa.analyze_route_priority(mock_ingresses)
print(f"\n  冲突数量: {len(conflicts)}")
for c in conflicts:
    print(f"  ⚠️  {c['description']}")
assert len(conflicts) == 1, f"期望 1 个冲突，实际 {len(conflicts)}"
print("  ✅ PASS")

# 验证 HTML 生成
html = sa._build_route_priority_html(conflicts)
assert "路由优先级变更警告" in html
assert "api-v2-svc" in html
assert "api-v1-svc" in html
print("  ✅ HTML 生成 PASS")

print("\n" + "=" * 70)
print("🎉 所有场景验证通过")
print("=" * 70)
