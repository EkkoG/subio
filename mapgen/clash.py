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
                "_protocol": {},
            }
        if ftype not in cache[p['type']]["_protocol"]:
            cache[p['type']]["_protocol"][ftype] = {}


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
            if k not in cache[p['type']]:
                cache[p['type']][k] = {}
            cache[p['type']][k][ftype] = {
                "origin": v
            }

gen_clash('mapgen/meta.json', 'clash-meta')
gen_clash('mapgen/clash.json', 'clash')

for ptype, config in cache.items():
    for k, v in config.items():
        allow_skip_keys = ['fingerprint', 'client_fingerprint', 'ip_version']
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