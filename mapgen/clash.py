import yaml
import json

# t = yaml.load(open('tt.yaml', 'r'), Loader=yaml.FullLoader)

# print(t)


cache = {}

def gen_clash(file, ftype):
    if file.endswith('.yaml'):
        t = yaml.load(open(file, 'r'), Loader=yaml.FullLoader)
    else:
        t = json.load(open(file, 'r'))

    for p in t['proxies']:

        if p['type'] not in cache:
            cache[p['type']] = {
                "protocol": {},
            }
        if ftype not in cache[p['type']]["protocol"]:
            cache[p['type']]["protocol"][ftype] = {}


        def gen(proxy):
            mm = {}
            for k, v in proxy.items():
                if isinstance(v, dict):
                    for k1, v1 in gen(v).items():
                        mm[f'{k}.{k1}'] = ".".join([k, k1])
                else:
                    mm[k] = k
            return mm

        for k,v in gen(p).items():
            k = k.replace('-', '_').replace('.', '_').lower()
            if 'map' not in cache[p['type']]:
                cache[p['type']]['map'] = {}
            if k not in cache[p['type']]['map']:
                cache[p['type']]['map'][k] = {}
            cache[p['type']]['map'][k][ftype] = {
                "origin": v
            }

gen_clash('mapgen/meta.yaml', 'clash-meta')
gen_clash('mapgen/clash.yaml', 'clash')
gen_clash('mapgen/stash.yaml', 'stash')

for ptype, config in cache.items():
    for k, v in config['map'].items():
        allow_skip_keys = ['fingerprint', 'client_fingerprint', 'ip_version', 'fast-open']
        all_platform = ['clash', 'clash-meta', 'stash']
        for platform in all_platform:
            if platform not in v:

                if k in allow_skip_keys:
                    cache[ptype]['map'][k][platform] = {
                        'policy': 'allow_skip',
                    }
                else:
                    cache[ptype]['map'][k][platform] = {
                        'policy': 'unsupport',
                    }

print(json.dumps(cache, indent=4))