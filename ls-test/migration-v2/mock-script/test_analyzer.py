#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Functional tests for the v2 NGINX Ingress migration analyzer."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from nginx_ingress_migration_analyzer import ANNOTATION_COMPATIBILITY, MigrationAnalyzer


def make_analyzer():
    class FakeAnalyzer:
        pass
    fa = FakeAnalyzer()
    fa.analyze_annotations = MigrationAnalyzer.analyze_annotations.__get__(fa)
    fa.calculate_migration_risk = MigrationAnalyzer.calculate_migration_risk.__get__(fa)
    return fa


def test_counts():
    counts = {level: len(annos) for level, annos in ANNOTATION_COMPATIBILITY.items()}
    total = sum(counts.values())
    print("Annotation counts:")
    for level, count in counts.items():
        print(f"  {level}: {count}")
    print(f"  Total: {total}")
    assert total == 130, f"Expected 130, got {total}"
    all_annos = []
    for annos in ANNOTATION_COMPATIBILITY.values():
        all_annos.extend(annos.keys())
    assert len(all_annos) == len(set(all_annos)), "Duplicate annotations"
    print("  No duplicates: PASS")


def test_risk_levels():
    ta = make_analyzer()
    r = ta.analyze_annotations({
        'nginx.ingress.kubernetes.io/rewrite-target': '/api/$2',
        'nginx.ingress.kubernetes.io/enable-cors': 'true',
        'nginx.ingress.kubernetes.io/canary': 'true',
    })
    risk, issues = ta.calculate_migration_risk(r)
    assert issues == 0
    print("  Test 1 (all compatible): PASS")
    r = ta.analyze_annotations({
        'nginx.ingress.kubernetes.io/rewrite-target': '/api',
        'nginx.ingress.kubernetes.io/configuration-snippet': 'x',
        'nginx.ingress.kubernetes.io/ssl-passthrough': 'true',
    })
    risk, issues = ta.calculate_migration_risk(r)
    assert issues > 0
    print("  Test 2 (has incompatible): PASS")
    r = ta.analyze_annotations({
        'nginx.ingress.kubernetes.io/limit-rps': '100',
        'nginx.ingress.kubernetes.io/enable-modsecurity': 'true',
    })
    risk, issues = ta.calculate_migration_risk(r)
    assert issues > 0
    print("  Test 3 (only replaceable): PASS")
    r = ta.analyze_annotations({
        'nginx.ingress.kubernetes.io/backend-protocol': 'GRPC',
        'nginx.ingress.kubernetes.io/load-balance': 'round_robin',
    })
    risk, issues = ta.calculate_migration_risk(r)
    assert issues > 0
    print("  Test 4 (partial compat): PASS")
    r = ta.analyze_annotations({
        'nginx.ingress.kubernetes.io/some-unknown-thing': 'value',
    })
    risk, issues = ta.calculate_migration_risk(r)
    assert issues > 0
    print("  Test 5 (unknown): PASS")
    r = ta.analyze_annotations({
        'nginx.ingress.kubernetes.io/proxy-buffering': 'on',
        'nginx.ingress.kubernetes.io/http2-push-preload': 'true',
    })
    risk, issues = ta.calculate_migration_risk(r)
    assert issues == 0
    print("  Test 6 (no migration needed): PASS")
    r = ta.analyze_annotations({
        'kubernetes.io/ingress.class': 'nginx',
        'some-other/annotation': 'value',
    })
    risk, issues = ta.calculate_migration_risk(r)
    assert issues == 0
    print("  Test 7 (non-nginx annotations): PASS")
    r = ta.analyze_annotations({
        'nginx.ingress.kubernetes.io/rewrite-target': '/api',
        'nginx.ingress.kubernetes.io/limit-rps': '100',
        'nginx.ingress.kubernetes.io/backend-protocol': 'HTTPS',
        'nginx.ingress.kubernetes.io/proxy-buffering': 'on',
    })
    assert len(r['完全兼容']) == 1
    assert len(r['可等价替换']) == 1
    assert len(r['部分兼容']) == 1
    assert len(r['无需迁移']) == 1
    print("  Test 8 (mixed scenario): PASS")
    r = ta.analyze_annotations({})
    risk, issues = ta.calculate_migration_risk(r)
    assert issues == 0
    print("  Test 9 (empty annotations): PASS")


def test_category_mapping():
    ta = make_analyzer()
    checks = {
        'nginx.ingress.kubernetes.io/temporal-redirect-code': '不兼容',
        'nginx.ingress.kubernetes.io/auth-url': '可等价替换',
        'nginx.ingress.kubernetes.io/auth-signin': '不兼容',
        'nginx.ingress.kubernetes.io/server-alias': '部分兼容',
        'nginx.ingress.kubernetes.io/proxy-body-size': '无需迁移',
        'nginx.ingress.kubernetes.io/ssl-passthrough': '不兼容',
        'nginx.ingress.kubernetes.io/backend-protocol': '部分兼容',
        'nginx.ingress.kubernetes.io/mirror-request-body': '无需迁移',
        'nginx.ingress.kubernetes.io/ssl-prefer-server-ciphers': '无需迁移',
        'nginx.ingress.kubernetes.io/session-cookie-samesite': '不兼容',
    }
    for anno, expected_cat in checks.items():
        r = ta.analyze_annotations({anno: 'test'})
        found_in = None
        for cat, items in r.items():
            if any(i['annotation'] == anno for i in items):
                found_in = cat
                break
        assert found_in == expected_cat, f"{anno}: expected '{expected_cat}', found '{found_in}'"
    print("  Category mapping spot-checks: PASS")


def test_all_annotations_resolvable():
    ta = make_analyzer()
    valid_cats = {'完全兼容', '可等价替换', '不兼容', '部分兼容', '无需迁移'}
    for compat_level, anno_dict in ANNOTATION_COMPATIBILITY.items():
        for anno in anno_dict:
            r = ta.analyze_annotations({anno: 'test'})
            total_found = sum(len(v) for v in r.values())
            assert total_found == 1, f"{anno}: expected 1 match, got {total_found}"
            for cat, items in r.items():
                if items:
                    assert cat in valid_cats, f"{anno}: unexpected category '{cat}'"
    print("  All 130 annotations resolvable: PASS")


if __name__ == '__main__':
    print("=== Testing annotation counts ===")
    test_counts()
    print("\n=== Testing risk levels ===")
    test_risk_levels()
    print("\n=== Testing category mapping ===")
    test_category_mapping()
    print("\n=== Testing all annotations resolvable ===")
    test_all_annotations_resolvable()
    print("\nAll tests passed!")
