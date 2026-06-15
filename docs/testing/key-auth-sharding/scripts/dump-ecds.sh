#!/bin/bash
# Dump ECDS key-auth config from envoy admin API
POD=$(kubectl get pods -n ls-test -l app=higress-gateway -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n ls-test "$POD" -c higress-gateway -- /bin/sh -c 'curl -s http://localhost:15000/config_dump?resource=ecds' 2>/dev/null | python3 -c "
import sys,json
raw=sys.stdin.read()
d=json.loads(raw)
configs=d.get('configs',[])
for c in configs:
    ecds=c.get('ecds_filters',[]) if 'ecds_filters' in c else []
    for f in ecds:
        name=f.get('ecds_filter',{}).get('name','')
        if 'key-auth' in name:
            print(f'=== {name} ===')
            typed_config=f.get('ecds_filter',{}).get('typed_config',{})
            pc=typed_config.get('plugin_config',{})
            print(json.dumps(pc, indent=2, ensure_ascii=False)[:5000])
"
