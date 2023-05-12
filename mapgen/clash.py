import yaml
import json

# t = yaml.load(open('tt.yaml', 'r'), Loader=yaml.FullLoader)

# print(t)


cache = {}

def gen_clash(file, ftype):
    t = json.load(open(file, 'r'))
    for p in t['proxies']:

        if p['type'] not in cache:
            cache[p['type']] = {
                "_protocol": {
                },
            }
        if ftype not in cache[p['type']]["_protocol"]:
            cache[p['type']]["_protocol"][ftype] = {
            }


        for k, v in p.items():
            if isinstance(v, dict):
                for k1, v1 in v.items():
                    key = f"{k}_{k1}".lower().replace('-', '_')
                    if key not in cache[p['type']]:
                        cache[p['type']][key] = {}
                    cache[p['type']][key][ftype] = {
                        "origin": f"{k}.{k1}",
                        }
            else:
                k = k.lower().replace('-', '_')
                if k not in cache[p['type']]:
                    cache[p['type']][k] = {}
                cache[p['type']][k][ftype] = {
                    "origin": k,
                    }

gen_clash('mapgen/meta.json', 'clash-meta')
gen_clash('mapgen/clash.json', 'clash')

for ptype, config in cache.items():
    for k, v in config.items():
        allow_skip_keys = ['fingerprint', 'client_fingerprint']
        all_platform = ['clash', 'clash-meta']
        for platform in all_platform:
            if platform not in v:

                if k in allow_skip_keys:
                    cache[ptype][k][platform] = {
                        'policy': 'allow_skip',
                    }
                else:
                    cache[ptype][k][platform] = {
                        'policy': 'unsupport',
                    }

print(json.dumps(cache, indent=4))