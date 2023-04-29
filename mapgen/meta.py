import yaml
import json

# t = yaml.load(open('tt.yaml', 'r'), Loader=yaml.FullLoader)

# print(t)

t = json.load(open('mapgen/tt.json', 'r'))

cache = {}
for p in t['proxies']:

    if p['type'] not in cache:
        cache[p['type']] = {
            "_protocol": {
                "clash-meta": {
                    "support": True,
                }
            },
        }


    for k, v in p.items():
        if isinstance(v, dict):
            for k1, v1 in v.items():
                key = f"{k}_{k1}".lower().replace('-', '_')
                cache[p['type']][key] = {}
                cache[p['type']][key]['clash-meta'] = {
                    "origin": f"{k}.{k1}",
                    "support": True,
                    }
        else:
            k = k.lower().replace('-', '_')
            cache[p['type']][k] = {}
            cache[p['type']][k]['clash-meta'] = {
                "origin": k,
                "support": True,
                }

print(json.dumps(cache, indent=4))