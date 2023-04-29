import yaml
import json

# t = yaml.load(open('tt.yaml', 'r'), Loader=yaml.FullLoader)

# print(t)

t = json.load(open('mapgen/t2.json', 'r'))

cache = json.load(open('map.json', 'r'))

for p in t['proxies']:

    if p['type'] not in cache:
        cache[p['type']] = {
            "_protocol": {
                "clash": {
                    "support": True,
                }
            },
        }
    else:
        if "_protocol" not in cache[p['type']]:
            cache[p['type']]["_protocol"] = {
                "clash": {
                    "support": True,
                }
            }
        else:
            cache[p['type']]["_protocol"]["clash"] = {
                    "support": True,
                }


    for k, v in p.items():
        if isinstance(v, dict):
            for k1, v1 in v.items():
                key = f"{k}_{k1}".lower().replace('-', '_')
                if key not in cache[p['type']]:
                    cache[p['type']][key] = {}
                cache[p['type']][key]['clash'] = {
                    "origin": f"{k}.{k1}",
                    "support": True,
                    }
        else:
            k = k.lower().replace('-', '_')
            if k not in cache[p['type']]:
                cache[p['type']][k] = {}
            cache[p['type']][k]['clash'] = {
                "origin": k,
                "support": True,
                }

print(json.dumps(cache, indent=4))