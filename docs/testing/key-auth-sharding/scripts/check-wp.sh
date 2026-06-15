#!/bin/bash
kubectl get wasmplugin key-auth.internal -n ls-test -o json 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
spec=d.get('spec',{})
print('resourceRefs:', spec.get('resourceRefs'))
print('resourceTemplateSchema:', spec.get('resourceTemplateSchema'))
dc=spec.get('defaultConfig',{})
print('defaultConfig keys:', list(dc.keys()) if dc else 'None')
print('matchRules count:', len(spec.get('matchRules',[])))
" 2>/dev/null || echo "WasmPlugin key-auth.internal 不存在"
