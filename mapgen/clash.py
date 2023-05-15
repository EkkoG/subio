import yaml
import json
from app.parser.clash import get_type

cache = {}

def gen_clash(file, ftype):
    if file.endswith('.yaml'):
        t = yaml.load(open(file, 'r'), Loader=yaml.FullLoader)
    else:
        t = json.load(open(file, 'r'))

    for p in t['proxies']:
        proxy_type = get_type(p)

        if proxy_type not in cache:
            cache[proxy_type] = {
                "protocol": {},
            }
        if ftype not in cache[proxy_type]["protocol"]:
            cache[proxy_type]["protocol"][ftype] = {}


        def gen(proxy):
            mm = {}
            for k, v in proxy.items():
                if isinstance(v, dict):
                    for k1, v1 in gen(v).items():
                        mm[f'{k}.{k1}'] = {
                            "origin": f'{k}.{k1}',
                        }
                elif isinstance(v, list):
                    # check if all items are str
                    if all(isinstance(i, str) for i in v):
                        mm[k] = {
                            "origin": k,
                            "is_list": True,
                        }
                    else:
                        #TODO: support list of dict
                        mm[k] = {
                            "origin": k,
                        }
                else:
                    mm[k] = {
                        "origin": k,
                    }
            return mm

        for k,v in gen(p).items():
            k = k.replace('-', '_').replace('.', '_').lower()
            if 'map' not in cache[proxy_type]:
                cache[proxy_type]['map'] = {}
            if k not in cache[proxy_type]['map']:
                cache[proxy_type]['map'][k] = {}
            cache[proxy_type]['map'][k][ftype] = v


def gen():
    gen_clash('mapgen/meta.yaml', 'clash-meta')
    gen_clash('mapgen/clash.yaml', 'clash')
    gen_clash('mapgen/stash.yaml', 'stash')

    for ptype, config in cache.items():
        all_platform = ['clash', 'clash-meta', 'stash']
        protocol = config['protocol'].copy()
        for k, v in protocol.items():
            for platform in all_platform:
                if platform not in protocol:
                    cache[ptype]['protocol'][platform] = {
                        'policy': 'unsupport',
                    }

        for k, v in config['map'].items():
            allow_skip_keys = ['fingerprint', 'client_fingerprint', 'ip_version', 'fast-open']
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