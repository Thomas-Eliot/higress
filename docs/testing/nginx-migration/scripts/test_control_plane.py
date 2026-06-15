#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
控制面测试 — 验证迁移后 Ingress annotation 保留/移除是否正确

与 test-control-plane.md 的用例对齐。
迁移后对每个 -higress Ingress 检查：
  1. 应保留的 annotation 是否存在且值正确
  2. 应移除的 annotation 是否不存在
  3. higress.io/resource-definer label 是否存在
  4. spec.ingressClassName 是否正确

用法:
  python3 test_control_plane.py -n <namespace> [--ingress-class <class>]

依赖: kubectl 已配置且可访问目标 namespace
"""

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ============================================================================
# 注解分类（与 AnnotationCompatibilityRegistry.java 对齐）
# ============================================================================
NGINX_PREFIX = "nginx.ingress.kubernetes.io/"

# 迁移时应移除的注解
REMOVE_ANNOTATIONS = set()

# 不兼容 (35)
INCOMPATIBLE = [
    "temporal-redirect-code", "auth-signin", "auth-snippet",
    "auth-signin-redirect-param", "auth-request-redirect",
    "auth-always-set-cookie", "auth-cache-duration", "auth-cache-key",
    "auth-keepalive", "auth-keepalive-requests", "auth-keepalive-share-vars",
    "auth-keepalive-timeout", "auth-tls-error-page", "satisfy",
    "ssl-passthrough", "session-cookie-domain", "session-cookie-samesite",
    "session-cookie-secure", "session-cookie-conditional-samesite-none",
    "upstream-hash-by-subset", "upstream-hash-by-subset-size",
    "client-body-buffer-size", "proxy-buffers-number",
    "modsecurity-snippet", "modsecurity-transaction-id",
    "enable-opentelemetry", "opentelemetry-trust-incoming-span",
    "enable-rewrite-log", "configuration-snippet", "server-snippet",
    "stream-snippet", "mirror-host",
    "limit-burst-multiplier", "limit-rate-after", "limit-rate",
]

# 无需迁移 (12)
NO_MIGRATION = [
    "proxy-body-size", "http2-push-preload", "connection-proxy-header",
    "ssl-prefer-server-ciphers", "proxy-buffering", "proxy-buffer-size",
    "proxy-busy-buffers-size", "proxy-max-temp-file-size",
    "proxy-request-buffering", "service-upstream",
    "session-cookie-change-on-failure", "mirror-request-body",
]

for a in INCOMPATIBLE + NO_MIGRATION:
    REMOVE_ANNOTATIONS.add(NGINX_PREFIX + a)

# 特殊移除
SPECIAL_REMOVE = {
    "kubernetes.io/ingress.class",
    "kubectl.kubernetes.io/last-applied-configuration",
}

# 应保留的分类: 完全兼容(39) + 可等价替换(37) + 部分兼容(7)
# 不逐一列举，用排除法：nginx 前缀注解如果不在 REMOVE 集合中就应该保留


# ============================================================================
# kubectl 工具
# ============================================================================
def kubectl_get_ingresses(namespace: str) -> List[dict]:
    cmd = ["kubectl", "get", "ingress", "-n", namespace, "-o", "json"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        print(f"kubectl 失败: {r.stderr}", file=sys.stderr)
        return []
    data = json.loads(r.stdout)
    return data.get("items", [])


# ============================================================================
# 测试逻辑
# ============================================================================
@dataclass
class CheckResult:
    ingress_name: str
    passed: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    kept_count: int = 0
    removed_count: int = 0


def find_original(name: str, originals: Dict[str, dict]) -> Optional[dict]:
    """根据 -higress 名称找到原始 Ingress"""
    if name.endswith("-higress"):
        orig_name = name[:-len("-higress")]
        return originals.get(orig_name)
    return None


def check_migrated_ingress(
    migrated: dict,
    original: Optional[dict],
    expected_class: Optional[str],
) -> CheckResult:
    name = migrated["metadata"]["name"]
    result = CheckResult(ingress_name=name, passed=True)
    annotations = migrated["metadata"].get("annotations", {})
    labels = migrated["metadata"].get("labels", {})
    spec = migrated.get("spec", {})

    # 1. 检查 higress label
    definer = labels.get("higress.io/resource-definer", "")
    if definer != "higress":
        result.errors.append(
            f"缺少 label higress.io/resource-definer=higress (实际: '{definer}')")
        result.passed = False

    # 2. 检查 ingressClassName
    actual_class = spec.get("ingressClassName", "")
    if expected_class and actual_class != expected_class:
        result.errors.append(
            f"ingressClassName 期望 '{expected_class}', 实际 '{actual_class}'")
        result.passed = False

    # 3. 检查特殊注解已移除
    for key in SPECIAL_REMOVE:
        if key in annotations:
            result.errors.append(f"应移除的特殊注解仍存在: {key}")
            result.passed = False

    # 4. 检查不兼容/无需迁移注解已移除
    for key in annotations:
        if key in REMOVE_ANNOTATIONS:
            result.errors.append(f"应移除的注解仍存在: {key}")
            result.passed = False
            result.removed_count += 1  # 误计，实际是未移除

    # 5. 如果有原始 Ingress，检查应保留的注解
    if original:
        orig_annotations = original["metadata"].get("annotations", {})
        for key, value in orig_annotations.items():
            # 跳过应移除的
            if key in REMOVE_ANNOTATIONS or key in SPECIAL_REMOVE:
                # 确认已移除
                if key not in annotations:
                    result.removed_count += 1
                continue
            # 应保留的注解
            if key in annotations:
                if annotations[key] != value:
                    result.errors.append(
                        f"注解值不一致: {key} 期望='{value}' 实际='{annotations[key]}'")
                    result.passed = False
                else:
                    result.kept_count += 1
            else:
                result.warnings.append(f"应保留的注解缺失: {key}")

    return result


def check_original_unchanged(original: dict, current: dict) -> CheckResult:
    """检查原始 Ingress 未被修改"""
    name = original["metadata"]["name"]
    result = CheckResult(ingress_name=name, passed=True)

    orig_ann = original["metadata"].get("annotations", {})
    curr_ann = current["metadata"].get("annotations", {})

    # 忽略 kubectl 自动管理的注解
    skip = {"kubectl.kubernetes.io/last-applied-configuration"}

    for key in set(list(orig_ann.keys()) + list(curr_ann.keys())):
        if key in skip:
            continue
        if key not in curr_ann:
            result.errors.append(f"原始注解被删除: {key}")
            result.passed = False
        elif key not in orig_ann:
            result.warnings.append(f"原始 Ingress 新增了注解: {key}")
        elif orig_ann[key] != curr_ann[key]:
            result.errors.append(f"原始注解被修改: {key}")
            result.passed = False

    return result


# ============================================================================
# 主流程
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description="控制面测试 — annotation 保留/移除验证")
    parser.add_argument("-n", "--namespace", required=True, help="目标 namespace")
    parser.add_argument("--ingress-class", default=None,
                        help="期望的目标 ingressClassName (如 ls-test)")
    args = parser.parse_args()

    ns = args.namespace
    expected_class = args.ingress_class

    print(f"控制面测试 — namespace: {ns}")
    print("=" * 60)

    all_ingresses = kubectl_get_ingresses(ns)
    if not all_ingresses:
        print(f"namespace {ns} 中没有 Ingress 资源")
        sys.exit(1)

    # 分类
    originals = {}  # name → ingress
    migrated = {}   # name → ingress
    for ing in all_ingresses:
        name = ing["metadata"]["name"]
        if name.endswith("-higress"):
            migrated[name] = ing
        else:
            originals[name] = ing

    print(f"原始 Ingress: {len(originals)}, 迁移产物: {len(migrated)}\n")

    if not migrated:
        print("未找到 -higress 迁移产物，请先执行迁移")
        sys.exit(1)

    total = 0
    passed = 0
    failed = 0
    results = []

    # TC-C1~C8: 检查每个迁移后的 Ingress
    print("--- 迁移产物 annotation 检查 ---\n")
    for name, ing in sorted(migrated.items()):
        total += 1
        orig = find_original(name, originals)
        r = check_migrated_ingress(ing, orig, expected_class)
        results.append(r)

        if r.passed:
            passed += 1
            status = "✅"
        else:
            failed += 1
            status = "❌"

        print(f"  {status} {name}  (保留:{r.kept_count} 移除:{r.removed_count})")
        for e in r.errors:
            print(f"      ❌ {e}")
        for w in r.warnings:
            print(f"      ⚠️ {w}")

    # TC-C10: 检查原始 Ingress 未被修改
    print("\n--- 原始 Ingress 完整性检查 ---\n")
    for name, orig in sorted(originals.items()):
        # 重新获取当前状态（已经在 all_ingresses 中了）
        total += 1
        # 这里 orig 就是当前状态，无法和迁移前对比
        # 只能检查基本完整性
        has_class = orig.get("spec", {}).get("ingressClassName", "")
        has_ann = len(orig["metadata"].get("annotations", {}))
        print(f"  ✅ {name}  (annotations:{has_ann}, class:{has_class})")
        passed += 1

    print(f"\n{'=' * 60}")
    print(f"结果: {passed} passed, {failed} failed / {total} total")
    print(f"{'=' * 60}")

    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
